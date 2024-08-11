#include <caml/mlvalues.h>
#include "capstone_disasm.h"


value disasm_capstone_init_stub(value unit) {
    return Val_int(disasm_capstone_init());
}
