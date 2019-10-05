namespace Frida.Fruity.Injector {
	public static async void inject (owned Gum.DarwinModule module, LLDB.Client lldb, Cancellable? cancellable) throws IOError {
		var session = new Session (module, lldb);
		yield session.run (cancellable);
	}

	private class Session : Object {
		public Gum.DarwinModule module {
			get;
			construct;
		}

		public LLDB.Client lldb {
			get;
			construct;
		}

		public Gum.CpuType cpu_type {
			get;
			construct;
			default = ARM64;
		}

		public uint page_size {
			get;
			construct;
			default = 16384;
		}

		public uint pointer_size {
			get;
			construct;
			default = 8;
		}

		private LLDB.Thread main_thread;

		private uint64 dyld_base;
		private Gee.HashMap<string, uint64?> dyld_symbols;
		private uint64 dlopen;
		private uint64 dlsym;

		private uint64 executable_base;

		public Session (Gum.DarwinModule module, LLDB.Client lldb) {
			Object (module: module, lldb: lldb);
		}

		public async void run (Cancellable? cancellable) throws IOError {
			try {
				var timer = new Timer ();

				yield lldb.enumerate_threads (thread => {
					main_thread = thread;
					return false;
				}, cancellable);
				printerr ("[*] Found main thread in %u ms\n", (uint) (timer.elapsed () * 1000.0));

				timer.reset ();
				yield probe_address_space (cancellable);
				printerr ("[*] Probed address space in %u ms\n", (uint) (timer.elapsed () * 1000.0));

				timer.reset ();
				yield ensure_libsystem_initialized (cancellable);
				printerr ("[*] Initialized libSystem in %u ms\n", (uint) (timer.elapsed () * 1000.0));

				timer.reset ();
				yield inject_module (cancellable);
				printerr ("[*] Injected module in %u ms\n", (uint) (timer.elapsed () * 1000.0));

				// yield lldb.detach (cancellable);
			} catch (GLib.Error e) {
				printerr ("OOPS: %s\n", e.message);
			}
		}

		private async void inject_module (Cancellable? cancellable) throws GLib.Error {
			size_t size = compute_footprint_size (module);
			uint64 base_address = yield lldb.allocate (size, "rw", cancellable);
			printerr ("base_address=%p size=0x%x\n", (void *) base_address, (uint) size);

			var buffer = lldb.make_buffer (module.image.bytes);

			GLib.Error? pending_error = null;

			module.enumerate_rebases (rebase => {
				switch (rebase.type) {
					case POINTER:
					case TEXT_ABSOLUTE32:
						break;
					default:
						pending_error = new IOError.FAILED ("Unsupported rebase type: %u", rebase.type);
						return false;
				}

				size_t offset = (size_t) (rebase.segment.file_offset + rebase.offset);
				uint64 address = buffer.read_pointer (offset);
				buffer.write_pointer (offset, address + rebase.slide);

				return true;
			});
			if (pending_error != null)
				throw pending_error;

			var symbols = new Gee.HashMap<string, Gee.HashMap<string, uint64?>> ();

			Gum.FoundDarwinBindFunc collect_bind = bind => {
				if (bind.type != POINTER) {
					pending_error = new IOError.FAILED ("Unsupported bind type: %u", bind.type);
					return false;
				}

				switch (bind.library_ordinal) {
					case SELF:
					case MAIN_EXECUTABLE:
					case FLAT_LOOKUP:
					case WEAK_LOOKUP:
						pending_error = new IOError.FAILED ("Unsupported bind ordinal: %d", bind.library_ordinal);
						return false;
					default:
						break;
				}

				unowned string module_name = module.get_dependency_by_ordinal (bind.library_ordinal);

				var group = symbols[module_name];
				if (group == null) {
					group = new Gee.HashMap<string, uint64?> ();
					symbols[module_name] = group;
				}

				group[bind.symbol_name] = 0;

				return true;
			};
			module.enumerate_binds (collect_bind);
			if (pending_error != null)
				throw pending_error;
			module.enumerate_lazy_binds (collect_bind);
			if (pending_error != null)
				throw pending_error;

			yield resolve_symbols (symbols, cancellable);

			Gum.FoundDarwinBindFunc perform_bind = bind => {
				unowned string module_name = module.get_dependency_by_ordinal (bind.library_ordinal);

				uint64 address = symbols[module_name][bind.symbol_name];
				if (address == 0) {
					bool is_weak = (bind.symbol_flags & Gum.DarwinBindSymbolFlags.WEAK_IMPORT) != 0;
					if (is_weak)
						return true;
					printerr ("WARNING: Unable to resolve symbol: %s\n", bind.symbol_name);
					return true;
					// pending_error = new IOError.FAILED ("Unable to resolve symbol: %s", bind.symbol_name);
					// return false;
				}

				buffer.write_pointer ((size_t) (bind.segment.file_offset + bind.offset), address + bind.addend);

				return true;
			};
			module.enumerate_binds (perform_bind);
			if (pending_error != null)
				throw pending_error;
			module.enumerate_lazy_binds (perform_bind);
			if (pending_error != null)
				throw pending_error;
		}

		private size_t compute_footprint_size (Gum.DarwinModule module) {
			size_t total = 0;

			foreach (unowned Gum.DarwinSegment segment in module.segments.data) {
				size_t size = (size_t) segment.vm_size;

				size_t remainder = size % page_size;
				if (remainder != 0)
					size += page_size - remainder;

				total += size;
			}

			return total;
		}

		private async void probe_address_space (Cancellable? cancellable) throws GLib.Error {
			dyld_symbols = new Gee.HashMap<string, uint64?> ();

			LLDB.Module? dyld = null;
			LLDB.Module? executable = null;
			uint64 slide = 0;
			yield lldb.enumerate_modules (module => {
				printerr ("%s\n", module.pathname);

				if (module.pathname == "/usr/lib/dyld") {
					dyld = module;
					var text_segment = dyld.segments[0];
					slide = dyld.load_address - text_segment.vmaddr;

					return true;
				}

				if (dyld != null) {
					executable = module;
					return false;
				}

				return true;
			}, cancellable);

			if (dyld == null)
				throw new IOError.FAILED ("Unable to locate dyld");
			dyld_base = dyld.load_address;

			if (executable == null)
				throw new IOError.FAILED ("Unable to locate executable");
			executable_base = executable.load_address;
			printerr ("[*] Executable base: %p\n", (void *) executable_base);

			var slices = new Gee.ArrayList<Bytes> ();
			size_t total_size = 0;
			foreach (var segment in dyld.segments) {
				printerr ("[*] dyld %s: %p->%p\n",
					segment.name,
					(void *) (segment.vmaddr + slide),
					(void *) (segment.vmaddr + slide + segment.vmsize));

				size_t size = (size_t) segment.filesize;
				if (size > 0) {
					var slice = yield lldb.read_byte_array (segment.vmaddr + slide, (size_t) segment.filesize,
						cancellable);
					slices.add (slice);

					total_size += size;
				}
			}

			var combined = new uint8[total_size];
			size_t offset = 0;
			foreach (var slice in slices) {
				size_t size = slice.get_size ();
				Memory.copy ((uint8 *) combined + offset, slice.get_data (), size);
				offset += size;
			}
			var dyld_blob = new Bytes.take ((owned) combined);

			// FileUtils.set_data ("/Users/oleavr/VMShared/dyld", dyld_blob.get_data ());

			Gum.DarwinModule dyld_mod;
			try {
				dyld_mod = new Gum.DarwinModule.from_blob (dyld_blob, Gum.DarwinPort.NULL, cpu_type, page_size);
			} catch (GLib.Error e) {
				throw new IOError.FAILED ("%s", e.message);
			}
			dyld_mod.base_address = dyld.load_address;
			dyld_mod.enumerate_symbols (symbol => {
				dyld_symbols[symbol.name] = symbol.address;
				return true;
			});

			dlopen = dyld_symbols.has_key ("_dlopen")
				? resolve_dyld_symbol ("_dlopen", "dlopen")
				: resolve_dyld_symbol ("_dlopen_internal", "dlopen");
			dlsym = dyld_symbols.has_key ("_dlsym")
				? resolve_dyld_symbol ("_dlsym", "dlsym")
				: resolve_dyld_symbol ("_dlsym_internal", "dlsym");
		}

		private uint64 resolve_dyld_symbol (string name, string nick) throws IOError {
			uint64? val = dyld_symbols[name];
			if (val == null)
				throw new IOError.FAILED ("Unsupported iOS version (%s not found)", nick);
			return val;
		}

		private async void ensure_libsystem_initialized (Cancellable? cancellable) throws GLib.Error {
			var fields = yield lldb.get_apple_dyld_fields (cancellable);

			var already_initialized = yield lldb.read_bool (fields.libsystem_initialized, cancellable);
			if (already_initialized)
				return;

			LLDB.Breakpoint? modern_breakpoint = null;
			uint64 launch_with_closure = 0;
			const string launch_with_closure_new_name = "__ZN4dyldL17launchWithClosureEPKN5dyld312launch_cache13binary_format7ClosureEPK15DyldSharedCachePK11mach_headermiPPKcSE_SE_PmSF_";
			const string launch_with_closure_old_name = "__ZN4dyldL17launchWithClosureEPKN5dyld37closure13LaunchClosureEPK15DyldSharedCachePKNS0_11MachOLoadedEmiPPKcSD_SD_PmSE_";
			if (dyld_symbols.has_key (launch_with_closure_new_name))
				launch_with_closure = dyld_symbols[launch_with_closure_new_name];
			else if (dyld_symbols.has_key (launch_with_closure_old_name))
				launch_with_closure = dyld_symbols[launch_with_closure_old_name];
			if (launch_with_closure != 0)
				modern_breakpoint = yield lldb.add_breakpoint (launch_with_closure, cancellable);

			uint64 initialize_main_executable = resolve_dyld_symbol ("__ZN4dyld24initializeMainExecutableEv", "initializeMainExecutable");
			LLDB.Breakpoint legacy_breakpoint = yield lldb.add_breakpoint (initialize_main_executable, cancellable);

			var exception = yield lldb.continue_until_exception (cancellable);

			LLDB.Breakpoint? hit_breakpoint = exception.breakpoint;
			if (hit_breakpoint == null)
				throw new IOError.FAILED ("Unexpected exception");

			yield legacy_breakpoint.remove (cancellable);

			if (modern_breakpoint != null)
				yield modern_breakpoint.remove (cancellable);

			if (hit_breakpoint == modern_breakpoint) {
				yield initialize_libsystem_from_modern_codepath (launch_with_closure, cancellable);
			} else {
				assert (hit_breakpoint == legacy_breakpoint);
				yield initialize_libsystem_from_legacy_codepath (cancellable);
			}

			yield lldb.write_bool (fields.libsystem_initialized, true, cancellable);
		}

		private async void initialize_libsystem_from_modern_codepath (uint64 launch_with_closure, Cancellable? cancellable)
				throws GLib.Error {
			uint64 run_initializers_call = yield find_dyld3_run_initializers_call (launch_with_closure, cancellable);

			var run_initializers_breakpoint = yield lldb.add_breakpoint (run_initializers_call, cancellable);
			var exception = yield lldb.continue_until_exception (cancellable);
			if (exception.breakpoint != run_initializers_breakpoint)
				throw new IOError.FAILED ("Unexpected exception while waiting for run_initializers_breakpoint");
		}

		private async uint64 find_dyld3_run_initializers_call (uint64 launch_with_closure, Cancellable? cancellable)
				throws GLib.Error {
			size_t max_size = 2048;
			var buffer = yield lldb.read_buffer (launch_with_closure, max_size, cancellable);

			/*
			 * Need to find code near “dyld3: launch, running initializers”, which is right
			 * before the call to runInitialzersBottomUp() (yes, Apple misspelled it).
			 *
			 * Which may look something like:
			 *
			 *     f9401788       ldr x8, [x28, 0x28]
			 *
			 * Broken down this is:
			 *
			 *                     0x28 (5*4)   x28    x8
			 *                         |         |     |
			 *     11 111 0 01 01 000000000101 11100 01000
			 *
			 * We will find a matching LDR with an unsigned offset of 0x28, ignoring the
			 * actual registers used. I.e.:
			 *
			 *     11 111 0 01 01 000000000101 xxxxx xxxxx
			 *
			 */
			for (size_t offset = 0; offset != max_size; offset += 4) {
				uint32 insn = buffer.read_uint32 (offset);
				if ((insn & 0xfffffc00U) == 0xf9401400U)
					return launch_with_closure + offset;
			}

			throw new IOError.FAILED ("Unable to probe dyld3 internals; please file a bug");
		}

		private async void initialize_libsystem_from_legacy_codepath (Cancellable? cancellable) throws GLib.Error {
			uint64 code = yield lldb.allocate (page_size, "rx", cancellable);

			var code_builder = lldb.make_buffer_builder ();

			uint64 ret_gadget = code;
			code_builder
				.append_uint32 (0xd65f03c0U); // ret

			uint64 get_thread_buf = code + code_builder.offset;
			code_builder
				.append_uint32 (0x58000060U)  // ldr x0, #0xc
				.append_uint32 (0xd65f03c0U); // ret

			size_t error_buf_literal_offset = code_builder.skip (4).offset;

			var helpers_builder = lldb.make_buffer_builder ();

			uint64 helpers_version = 1;
			uint64 acquire_global_dyld_lock = ret_gadget;
			uint64 release_global_dyld_lock = ret_gadget;
			uint64 get_thread_buffer_for_dlerror = get_thread_buf;

			helpers_builder
				.append_pointer (helpers_version)
				.append_pointer (acquire_global_dyld_lock)
				.append_pointer (release_global_dyld_lock)
				.append_pointer (get_thread_buffer_for_dlerror);

			size_t libsystem_string_offset = helpers_builder.offset;
			helpers_builder.append_string ("/usr/lib/libSystem.B.dylib");

			size_t error_buffer_offset = helpers_builder.offset;
			const uint error_buffer_size = 1024;
			helpers_builder.skip (error_buffer_size);

			var helpers_buf = helpers_builder.build ();
			uint64 helpers = yield lldb.allocate (helpers_buf.get_size (), "rw", cancellable);
			yield lldb.write_byte_array (helpers, helpers_buf, cancellable);

			uint64 libsystem_string = helpers + libsystem_string_offset;

			code_builder.write_pointer (error_buf_literal_offset, helpers + error_buffer_offset);
			yield lldb.write_byte_array (code, code_builder.build (), cancellable);

			uint64 register_thread_helpers =
				resolve_dyld_symbol ("__ZL21registerThreadHelpersPKN4dyld16LibSystemHelpersE", "registerThreadHelpers");
			yield invoke_remote_function (register_thread_helpers, { helpers }, null, cancellable);

			/*
			var strcmp_impl = resolve_dyld_symbol ("_strcmp", "strcmp");
			var modinit_start = resolve_dyld_symbol (
				"__ZN16ImageLoaderMachO18doModInitFunctionsERKN11ImageLoader11LinkContextE",
				"doModInitStart");
			var modinit_end = resolve_dyld_symbol (
				"__ZN16ImageLoaderMachO16doGetDOFSectionsERKN11ImageLoader11LinkContextERNSt3__16vectorINS0_7DOFInfoENS4_9allocatorIS6_EEEE",
				"doModInitEnd");
			var strcmp_handler = new ModinitStrcmpHandler (strcmp_impl, modinit_start, modinit_end);
			var strcmp_breakpoint = yield lldb.add_breakpoint (strcmp_impl, cancellable);
			*/
			ExceptionHandler? strcmp_handler = null;

			yield invoke_remote_function (dlopen, { libsystem_string, 9, 0 }, strcmp_handler, cancellable);

			/*
			yield strcmp_breakpoint.remove (cancellable);
			*/

			yield lldb.deallocate (helpers, cancellable);

			yield lldb.deallocate (code, cancellable);
		}

		private class ModinitStrcmpHandler : Object, ExceptionHandler {
			public uint64 strcmp_impl {
				get;
				construct;
			}

			public uint64 modinit_start {
				get;
				construct;
			}

			public uint64 modinit_end {
				get;
				construct;
			}

			public ModinitStrcmpHandler (uint64 strcmp_impl, uint64 modinit_start, uint64 modinit_end) {
				Object (
					strcmp_impl: strcmp_impl,
					modinit_start: modinit_start,
					modinit_end: modinit_end
				);
			}

			public async bool try_handle_exception (LLDB.Exception exception, Cancellable? cancellable) throws GLib.Error {
				uint64 pc = exception.context["pc"];
				if (pc != strcmp_impl)
					return false;

				var thread = exception.thread;

				uint64 ret_address = exception.context["lr"];
				if (ret_address >= modinit_start && ret_address < modinit_end) {
					yield thread.write_register ("x0", 0, cancellable);
					yield thread.write_register ("pc", ret_address, cancellable);
				}

				return true;
			}
		}

		private async uint64 invoke_remote_function (uint64 impl, uint64[] args, ExceptionHandler? exception_handler,
				Cancellable? cancellable) throws GLib.Error {
			var old_register_state = yield main_thread.save_register_state (cancellable);

			var sp = yield main_thread.read_register ("sp", cancellable);
			yield main_thread.write_register ("sp", sp - 128, cancellable);

			yield main_thread.write_register ("pc", impl, cancellable);
			yield main_thread.write_register ("lr", 1337, cancellable);

			uint arg_id = 1;
			foreach (uint64 arg_val in args) {
				yield main_thread.write_register ("arg%u".printf (arg_id), arg_val, cancellable);
				arg_id++;
			}

			while (true) {
				var exception = yield lldb.continue_until_exception (cancellable);

				uint64 pc = exception.context["pc"];
				if (pc == 1337)
					break;

				if (exception_handler != null) {
					bool handled = yield exception_handler.try_handle_exception (exception, cancellable);
					if (handled)
						continue;
				}

				throw new IOError.FAILED ("Invocation of 0x%" + uint64.FORMAT_MODIFIER + "x crashed at 0x%" +
					uint64.FORMAT_MODIFIER + "x", impl, pc);
			}

			uint64 result = yield main_thread.read_register ("x0", cancellable);

			yield main_thread.restore_register_state (old_register_state, cancellable);

			return result;
		}

		private async void resolve_symbols (Gee.HashMap<string, Gee.HashMap<string, uint64?>> symbols, Cancellable? cancellable)
				throws GLib.Error {
			uint64 code = yield lldb.allocate (page_size, "rx", cancellable);

			var code_builder = lldb.make_buffer_builder ();
			foreach (var insn in SYMBOL_RESOLVER_CODE)
				code_builder.append_uint32 (insn);
			yield lldb.write_byte_array (code, code_builder.build (), cancellable);

			var state_builder = lldb.make_buffer_builder ();

			var groups = new Gee.ArrayList<SymbolResolveGroup> ();
			var strv_builder = new StringVectorBuilder (state_builder);
			uint num_symbols = 0;

			foreach (var module_entry in symbols.entries) {
				unowned string module_name = module_entry.key;

				var group = new SymbolResolveGroup (module_name);
				groups.add (group);

				strv_builder.append_string (module_name);

				var names = group.symbol_names;
				foreach (var symbol_name in module_entry.value.keys) {
					names.add (symbol_name);

					strv_builder.append_string (demangle (symbol_name));

					num_symbols++;
				}

				strv_builder.append_terminator ();
			}
			strv_builder.append_terminator ();

			var input_vector_offset = strv_builder.append_placeholder ();

			var output_vector_offset = state_builder.offset;
			size_t output_vector_size = num_symbols * pointer_size;
			state_builder.skip (output_vector_size);

			var state_size = state_builder.offset;
			uint64 state = yield lldb.allocate (state_size, "rw", cancellable);
			strv_builder.build (state);
			var state_blob = state_builder.build ();
			FileUtils.set_data ("/Users/oleavr/VMShared/state.bin", state_blob.get_data ());
			printerr ("state=%p\n", (void *) state);
			printerr ("state_size=0x%x\n", (uint) state_size);
			printerr ("input_vector_offset=0x%x\n", (uint) input_vector_offset);
			printerr ("output_vector_offset=0x%x\n", (uint) output_vector_offset);
			yield lldb.write_byte_array (state, state_blob, cancellable);

			uint64 input_vector_address = state + input_vector_offset;
			uint64 output_vector_address = state + output_vector_offset;
			uint64 caller_module = executable_base;
			// yield lldb.enumerate_modules (module => {
			// 	if (module.pathname == "/System/Library/Frameworks/Foundation.framework/Foundation") {
			// 		printerr ("PRETENDING IT IS FOUNDATION\n");
			// 		caller_module = module.load_address;
			// 		return false;
			// 	}
			// 	return true;
			// }, cancellable);

			var old_register_state = yield main_thread.save_register_state (cancellable);

			var sp = yield main_thread.read_register ("sp", cancellable);
			yield main_thread.write_register ("sp", sp - 128, cancellable);

			yield main_thread.write_register ("pc", code, cancellable);
			yield main_thread.write_register ("lr", 1337, cancellable);

			yield main_thread.write_register ("x19", dlopen, cancellable);
			yield main_thread.write_register ("x20", dlsym, cancellable);
			yield main_thread.write_register ("x21", caller_module, cancellable);
			yield main_thread.write_register ("x22", input_vector_address, cancellable);
			yield main_thread.write_register ("x23", output_vector_address, cancellable);

			var exception = yield lldb.continue_until_exception (cancellable);
			uint64 pc = exception.context["pc"];
			uint64 last_instruction = code + ((SYMBOL_RESOLVER_CODE.length - 1) * 4);
			if (pc != last_instruction) {
				var context = exception.context;
				uint64 x0 = context["x0"];
				uint64 x1 = context["x1"];
				uint64 x2 = context["x2"];
				uint64 x20 = context["x20"];
				uint64 x21 = context["x21"];
				uint64 x22 = context["x22"];
				uint64 x23 = context["x23"];
				printerr ("x0: %p\n", (void *) x0);
				printerr ("x1: %p\n", (void *) x1);
				printerr ("x2: %p\n", (void *) x2);
				printerr ("x20: %p\n", (void *) x20);
				printerr ("x21: %p\n", (void *) x21);
				printerr ("x22: %p\n", (void *) x22);
				printerr ("x23: %p\n", (void *) x23);
				yield lldb.enumerate_modules (module => {
					printerr ("MODULE at %p: %s\n", (void *) module.load_address, module.pathname);
					return true;
				}, cancellable);

				var mem = yield lldb.read_byte_array (x1, 32, cancellable);
				FileUtils.set_data ("/Users/oleavr/VMShared/x1.bin", mem.get_data ());

				throw new IOError.FAILED ("Invocation of resolver 0x%" + uint64.FORMAT_MODIFIER + "x crashed at 0x%" +
					uint64.FORMAT_MODIFIER + "x", code, pc);
			}

			yield main_thread.restore_register_state (old_register_state, cancellable);

			var output_vector = yield lldb.read_buffer (output_vector_address, output_vector_size, cancellable);
			size_t offset = 0;
			foreach (var group in groups) {
				var result_group = symbols[group.module_name];

				foreach (var symbol_name in group.symbol_names) {
					result_group[symbol_name] = output_vector.read_pointer (offset);

					offset += pointer_size;
				}
			}

			yield lldb.deallocate (state, cancellable);
			yield lldb.deallocate (code, cancellable);
		}

		private string demangle (string symbol_name) {
			return (symbol_name[0] == '_')
				? symbol_name.substring (1)
				: symbol_name;
		}

		private class SymbolResolveGroup {
			public string module_name {
				get;
				private set;
			}

			public Gee.ArrayList<string> symbol_names {
				get;
				private set;
			}

			public SymbolResolveGroup (string module_name) {
				this.module_name = module_name;
				this.symbol_names = new Gee.ArrayList<string> ();
			}
		}

		private class StringVectorBuilder {
			private LLDB.BufferBuilder buffer_builder;
			private Gee.ArrayList<int> vector = new Gee.ArrayList<int> ();
			private size_t start_offset;

			public uint length {
				get {
					return vector.size;
				}
			}

			public StringVectorBuilder (LLDB.BufferBuilder buffer_builder) {
				this.buffer_builder = buffer_builder;
			}

			public void append_string (string val) {
				var offset = buffer_builder.offset;
				buffer_builder.append_string (val);
				vector.add ((int) offset);
			}

			public void append_terminator () {
				vector.add (-1);
			}

			public size_t append_placeholder () {
				start_offset = buffer_builder.offset;

				buffer_builder.skip (vector.size * buffer_builder.pointer_size);

				return start_offset;
			}

			public void build (uint64 address) {
				var vector_offset = start_offset;
				var pointer_size = buffer_builder.pointer_size;

				foreach (int string_offset in vector) {
					uint64 val = (string_offset != -1) ? address + string_offset : 0;
					buffer_builder.write_pointer (vector_offset, val);

					vector_offset += pointer_size;
				}
			}
		}

		private const uint32[] SYMBOL_RESOLVER_CODE = {
			// start:
			0xf94002c0U, // ldr x0, [x22]
			0xb4000320U, // cbz x0, done
			0xd2800121U, // mov x1, RTLD_LAZY | RTLD_GLOBAL
			0xaa1503e2U, // mov x2, x21 (caller_module)
			//0xd63f0260U, // blr x19 (dlopen)
			0x92800020U, // mov x0, -2 (RTLD_DEFAULT)
			//0x92800000U, // mov x0, #-0x1 (RTLD_NEXT)
			0xaa0003f8U, // mov x24, x0
			0x910022d6U, // add x22, x22, #0x8 (input_vector++)
			0xb40001a0U, // cbz x0, skip_next_symbol
			0x14000003U, // b resolve_next_symbol

			// resolve_next_module:
			0x910022d6U, // add x22, x22, #0x8 (input_vector++)
			0x17fffff6U, // b start

			// resolve_next_symbol:
			0xf94002c1U, // ldr x1, [x22]
			0xb4ffffa1U, // cbz x1, resolve_next_module
			0xaa1803e0U, // mov x0, x24
			0xaa1503e2U, // mov x2, x21
			0xd63f0280U, // blr x20 (dlsym)
			//0xd4200000U, // brk #0
			0xf90002e0U, // str x0, [x23]
			0x910022d6U, // add x22, x22, #0x8 (input_vector++)
			0x910022f7U, // add x23, x23, #0x8 (output_vector++)
			0x17fffff8U, // b resolve_next_symbol

			// skip_next_symbol:
			0xf94002c0U, // ldr x0, [x22]
			0xb4fffe80U, // cbz x0, resolve_next_module
			0xf90002ffU, // str xzr, [x23]
			0x910022d6U, // add x22, x22, #0x8 (input_vector++)
			0x910022f7U, // add x23, x23, #0x8 (output_vector++)
			0x17fffffbU, // b skip_next_symbol

			// done:
			0xd4200000U, // brk #0
		};
	}

	private interface ExceptionHandler : Object {
		public abstract async bool try_handle_exception (LLDB.Exception exception, Cancellable? cancellable)
			throws GLib.Error;
	}
}
