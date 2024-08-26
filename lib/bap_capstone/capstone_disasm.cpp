#include <iostream>
#include <memory>
#include <algorithm>
#include <map>
#include <vector>
#include <exception>
#include <cerrno>
#include <sstream>
#include <system_error>
#include <inttypes.h>

#include <capstone/capstone.h>
#include <capstone/x86.h>
#include <capstone/platform.h>


#include "capstone_disasm.hpp"
#include "disasm.hpp"

template <typename T>
using shared_ptr = std::shared_ptr<T>;


// re-using partial MemoryObject
class MemoryObject {
public:
    bap::memory mem;        // TODO: make this private later
                            // and give access to data for cs_disasm
    MemoryObject() : mem() {}

    MemoryObject(const bap::memory &mem) : mem(mem) {}

    void set_memory(const bap::memory &new_mem) {
        mem = new_mem;
    }

    uint64_t getBase() const {
        return mem.base;
    }

    uint64_t getExtent() const {
        return mem.loc.len;
    }


    bool is_mapped(uint64_t addr) const {
        return (addr >= mem.base) && (addr - mem.base < mem.loc.len);
    }
};

bap::table table_from_string(const std::string &data) {
    bap::table res;
    res.data = data.c_str();
    res.size = data.length();
    return res;
}

class capstone_disassembler : public bap::disassembler_interface {
    shared_ptr<MemoryObject>    mem;
    bap::insn                   current;
    bap::table                  ins_tab, reg_tab;
    const int                   debug_level;

    // capstone stuff
    static csh      cap_handle; // C++ requires this to be a static.
                                // TODO: convert this to Singleton Class
    static cs_insn  *cap_insn;
    static size_t   cap_count;

    capstone_disassembler(int debug_level)
        : debug_level(debug_level), current(invalid_insn({0,0})) {}

public:
    ~capstone_disassembler() {
        if (cap_insn) {
            cs_free(cap_insn, cap_count);
        }
        cs_close(&cap_handle);
    }


    // TODO: check if I should return of type capstone_disassembler
    // or should return disassembler_interface
    static bap::result<capstone_disassembler>
    create(int debug_level) {

        // trying to imitate the LLVM code
        // ignoring name and cpu as I will support only x86_64

        // initialize capstone
        if (cs_open(CS_ARCH_X86, CS_MODE_64, &cap_handle) != CS_ERR_OK) {

            if (debug_level > 0) {
                std::cerr << "Failed to initialize capstone (cs_open)\n";
            }

            return {nullptr, {bap_disasm_unknown_error}};
        }


        // TODO: Need to more checks later
        shared_ptr<capstone_disassembler> self(new capstone_disassembler(debug_level));

        return {self, {0}};
    }



    bap::table insn_table() const {
        // TODO: FIXME
        return ins_tab;
    }

    bap::table reg_table() const {
        // TODO: FIXME
        return reg_tab;
    }


    void set_memory(bap::memory m) {
        mem->set_memory(m);
    }

    bap::insn get_insn() const {
        return current;
    }

    void step (uint64_t pc) {

        // capstone x86
        cs_x86  *cap_x86 = NULL;

        current = invalid_insn(bap::location{0, 1});
        auto base = mem->getBase();

        if (pc < base) {
            current = invalid_insn(bap::location{0, 1});
            return;
        } else if (pc > base + mem->getExtent()) {
            auto off = static_cast<int>(mem->getExtent() - 1);
            current = invalid_insn(bap::location{off, 1});
            return;
        }

        u_int64_t size = 0;
        int off = pc - base;
        int len = mem->getExtent() - off;

        // FIXME: probably a blunder casting from "char *" to "uint8_t *", check later
        cap_count = cs_disasm(cap_handle, (uint8_t *)(mem->mem.data), len, pc, 1, &cap_insn);

        // not sure if I should handle the prefix thing like how it is handled in the llvm_disasm.cpp
        if (cap_count > 0) {
            // now insn should contain all the data we need.

            current.code = cap_insn->id;
            // current.name = cap_insn->mnemonic; // TODO: fix this once the insn_table and reg_table is fixed

            if (&cap_insn->detail != NULL) {
                cap_x86 = &(cap_insn->detail->x86);
                // can pretty much get most of the info as show in
                // https://github.com/capstone-engine/capstone/blob/next/tests/test_x86.c

            }


        } else {
            // TODO: change the location later
            current = invalid_insn(bap::location{0, 1});
            if (debug_level > 0) {
                std::cerr << "Capstone Error: Failed to disassemble at"
                            << " pc " << pc << "\n";
            }
        }

    }

    std::string get_asm() const {
        // TODO: FIXME
        std::stringstream   ss;

        if (current.code != 0) {
            // check if I need put newline at the end of this.
            ss << cap_insn->mnemonic << "\t" << cap_insn->op_str;
            return ss.str();
        }

        return "#undefined";
    }

    bool satisfies(bap_disasm_insn_p_type p) const{
        // TODO: FIXME
        return true;
    }

    bool supports(bap_disasm_insn_p_type p) const {
        return true;
    }

private:
    bap::insn invalid_insn(bap::location loc) const {
        return {0, 0L, loc};
    }

};

struct create_capstone_disassembler : public bap::disasm_factory {
    // some private fields handle stuff
    std::stringstream err;
public:
    int init() {

        // TODO: not sure what kind of initialization I need to do here.
        // TODO: something to do with supported languages and stuff.
        // TODO: some capstone initialization?

        return 0;
    }

    void dump_errors() {
        std::cerr << err.str();
    }

    bap::result<bap::disassembler_interface>
    create(const char *triple, const char *cpu, int debug_level) {
        bap::result<bap::disassembler_interface> r;

        // we only support amd64/x86-64 (PIE)
        if (std::string(triple) != "amd64") {
            if (debug_level > 0) {
                err << "capstone_disasm: unsupported target\n";
                err << "\t\t only x86-64/amd64 is supported\n";
            }
            r.err = bap_disasm_unsupported_target;
        } else {
            // TODO: FIXME
            // auto capstone = capstone_disassembler::create(triple, cpu, debug_level);
            // r.dis = capstone.dis;
            // if (!r.dis) {
            //     r.err = capstone.err;
            // }
        }
        return r;
    }

};



int disasm_capstone_init() {

    // setup and do some checks
    auto factory = std::make_shared<create_capstone_disassembler>();
    int result = factory->init();
    if (result < 0) {
        factory->dump_errors();
        return result;
    } else {
        return bap::register_disassembler("capstone", factory);
    }

}
