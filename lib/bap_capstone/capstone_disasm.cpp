#include <iostream>
#include <memory>
#include <algorithm>
#include <map>
#include <vector>
#include <exception>
#include <cerrno>
#include <sstream>
#include <system_error>

#include <capstone/capstone.h>
#include <capstone/x86.h>
#include <capstone/platform.h>


#include "capstone_disasm.hpp"
#include "disasm.hpp"


// re-using partial MemoryObject from llvm_disasm.cpp
class MemoryObject {
    const char *data;
    uint64_t base;
    uint64_t size;
    uint64_t offset;
public:
    MemoryObject() :
        data(NULL),
        base(0),
        size(0),
        offset(0)
        {}

    explicit MemoryObject(const bap::memory &mem) {
        set_memory(mem);
    }

    virtual ~MemoryObject() {}

    uint64_t getBase() const {
        return base;
    }

    uint64_t getExtent() const {
        return size;
    }

    void set_memory(const bap::memory &m) {
        data = m.data;
        base = m.base;
        size = m.loc.len;
        offset = m.loc.off;
    }

    // TODO: FIXME (yet to figure out what to do with the
    //              view function from llvm_disasm MemoryObject)

};


class capstone_disassembler : public bap::disassembler_interface {
    bap::insn   current;
    bap::table  ins_tab, reg_tab;
public:


    bap::table insn_table() const {
        // TODO: FIXME
        return ins_tab;
    }

    bap::table reg_table() const {
        // TODO: FIXME
        return reg_tab;
    }


    void set_memory(bap::memory mem) {
        // TODO: FIXME
    }

    bap::insn get_insn() const {
        return current;
    }

    std::string get_asm() const {
        // TODO: FIXME
        return "#undefined";
    }

    bool satisfies(bap_disasm_insn_p_type p) {
        // TODO: FIXME
        return true;
    }

    bool supports(bap_disasm_insn_p_type p) const {
        return true;
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
