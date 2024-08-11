external capstone_init : unit -> int = "disasm_capstone_init_stub"

let init () =
  if capstone_init () < 0 then
    failwith "failed to initialize capstone backend. See stderr for information"
