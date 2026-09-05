//! Fixed, one-file-per-instruction VM opcode templates.

mod lua51_00_move;
mod lua51_01_loadk;
mod lua51_02_loadbool;
mod lua51_03_loadnil;
mod lua51_04_getupval;
mod lua51_05_getglobal;
mod lua51_06_gettable;
mod lua51_07_setglobal;
mod lua51_08_setupval;
mod lua51_09_settable;
mod lua51_10_newtable;
mod lua51_11_self;
mod lua51_12_add;
mod lua51_13_sub;
mod lua51_14_mul;
mod lua51_15_div;
mod lua51_16_mod;
mod lua51_17_pow;
mod lua51_18_unm;
mod lua51_19_not;
mod lua51_20_len;
mod lua51_21_concat;
mod lua51_22_jmp;
mod lua51_23_eq;
mod lua51_24_lt;
mod lua51_25_le;
mod lua51_26_test;
mod lua51_27_testset;
mod lua51_28_call;
mod lua51_29_tailcall;
mod lua51_30_return;
mod lua51_31_forloop;
mod lua51_32_forprep;
mod lua51_33_tforloop;
mod lua51_34_setlist;
mod lua51_35_close;
mod lua51_36_closure;
mod lua51_37_vararg;
mod luau_00_nop;
mod luau_01_break;
mod luau_02_loadnil;
mod luau_03_loadb;
mod luau_04_loadn;
mod luau_05_loadk;
mod luau_06_move;
mod luau_07_getglobal;
mod luau_08_setglobal;
mod luau_09_getupval;
mod luau_10_setupval;
mod luau_11_closeupvals;
mod luau_12_getimport;
mod luau_13_gettable;
mod luau_14_settable;
mod luau_15_gettableks;
mod luau_16_settableks;
mod luau_17_gettablen;
mod luau_18_settablen;
mod luau_19_newclosure;
mod luau_20_namecall;
mod luau_21_call;
mod luau_22_return;
mod luau_23_jump;
mod luau_24_jumpback;
mod luau_25_jumpif;
mod luau_26_jumpifnot;
mod luau_27_jumpifeq;
mod luau_28_jumpifle;
mod luau_29_jumpiflt;
mod luau_30_jumpifnoteq;
mod luau_31_jumpifnotle;
mod luau_32_jumpifnotlt;
mod luau_33_add;
mod luau_34_sub;
mod luau_35_mul;
mod luau_36_div;
mod luau_37_mod;
mod luau_38_pow;
mod luau_39_addk;
mod luau_40_subk;
mod luau_41_mulk;
mod luau_42_divk;
mod luau_43_modk;
mod luau_44_powk;
mod luau_45_and;
mod luau_46_or;
mod luau_47_andk;
mod luau_48_ork;
mod luau_49_concat;
mod luau_50_not;
mod luau_51_minus;
mod luau_52_length;
mod luau_53_newtable;
mod luau_54_duptable;
mod luau_55_setlist;
mod luau_56_fornprep;
mod luau_57_fornloop;
mod luau_58_forgloop;
mod luau_59_forgprep_inext;
mod luau_60_fastcall3;
mod luau_61_forgprep_next;
mod luau_62_nativecall;
mod luau_63_getvarargs;
mod luau_64_dupclosure;
mod luau_65_prepvarargs;
mod luau_66_loadkx;
mod luau_67_jumpx;
mod luau_68_fastcall;
mod luau_69_coverage;
mod luau_70_capture;
mod luau_71_subrk;
mod luau_72_divrk;
mod luau_73_fastcall1;
mod luau_74_fastcall2;
mod luau_75_fastcall2k;
mod luau_76_forgprep;
mod luau_77_jumpxeqknil;
mod luau_78_jumpxeqkb;
mod luau_79_jumpxeqkn;
mod luau_80_jumpxeqks;
mod luau_81_idiv;
mod luau_82_idivk;
mod luau_83_getudataks;
mod luau_84_setudataks;
mod luau_85_namecalludata;
mod luau_86_newclassmember;
mod luau_87_callfb;
mod luau_88_cmpproto;
mod luau_89_fastpcall;
mod luau_90_newclass;

const LUA51: [fn() -> &'static str; 38] = [
    lua51_00_move::code,
    lua51_01_loadk::code,
    lua51_02_loadbool::code,
    lua51_03_loadnil::code,
    lua51_04_getupval::code,
    lua51_05_getglobal::code,
    lua51_06_gettable::code,
    lua51_07_setglobal::code,
    lua51_08_setupval::code,
    lua51_09_settable::code,
    lua51_10_newtable::code,
    lua51_11_self::code,
    lua51_12_add::code,
    lua51_13_sub::code,
    lua51_14_mul::code,
    lua51_15_div::code,
    lua51_16_mod::code,
    lua51_17_pow::code,
    lua51_18_unm::code,
    lua51_19_not::code,
    lua51_20_len::code,
    lua51_21_concat::code,
    lua51_22_jmp::code,
    lua51_23_eq::code,
    lua51_24_lt::code,
    lua51_25_le::code,
    lua51_26_test::code,
    lua51_27_testset::code,
    lua51_28_call::code,
    lua51_29_tailcall::code,
    lua51_30_return::code,
    lua51_31_forloop::code,
    lua51_32_forprep::code,
    lua51_33_tforloop::code,
    lua51_34_setlist::code,
    lua51_35_close::code,
    lua51_36_closure::code,
    lua51_37_vararg::code,
];

pub(super) fn lua51(opcode: usize) -> &'static str {
    LUA51[opcode]()
}

const LUAU: [fn() -> &'static str; 91] = [
    luau_00_nop::code,
    luau_01_break::code,
    luau_02_loadnil::code,
    luau_03_loadb::code,
    luau_04_loadn::code,
    luau_05_loadk::code,
    luau_06_move::code,
    luau_07_getglobal::code,
    luau_08_setglobal::code,
    luau_09_getupval::code,
    luau_10_setupval::code,
    luau_11_closeupvals::code,
    luau_12_getimport::code,
    luau_13_gettable::code,
    luau_14_settable::code,
    luau_15_gettableks::code,
    luau_16_settableks::code,
    luau_17_gettablen::code,
    luau_18_settablen::code,
    luau_19_newclosure::code,
    luau_20_namecall::code,
    luau_21_call::code,
    luau_22_return::code,
    luau_23_jump::code,
    luau_24_jumpback::code,
    luau_25_jumpif::code,
    luau_26_jumpifnot::code,
    luau_27_jumpifeq::code,
    luau_28_jumpifle::code,
    luau_29_jumpiflt::code,
    luau_30_jumpifnoteq::code,
    luau_31_jumpifnotle::code,
    luau_32_jumpifnotlt::code,
    luau_33_add::code,
    luau_34_sub::code,
    luau_35_mul::code,
    luau_36_div::code,
    luau_37_mod::code,
    luau_38_pow::code,
    luau_39_addk::code,
    luau_40_subk::code,
    luau_41_mulk::code,
    luau_42_divk::code,
    luau_43_modk::code,
    luau_44_powk::code,
    luau_45_and::code,
    luau_46_or::code,
    luau_47_andk::code,
    luau_48_ork::code,
    luau_49_concat::code,
    luau_50_not::code,
    luau_51_minus::code,
    luau_52_length::code,
    luau_53_newtable::code,
    luau_54_duptable::code,
    luau_55_setlist::code,
    luau_56_fornprep::code,
    luau_57_fornloop::code,
    luau_58_forgloop::code,
    luau_59_forgprep_inext::code,
    luau_60_fastcall3::code,
    luau_61_forgprep_next::code,
    luau_62_nativecall::code,
    luau_63_getvarargs::code,
    luau_64_dupclosure::code,
    luau_65_prepvarargs::code,
    luau_66_loadkx::code,
    luau_67_jumpx::code,
    luau_68_fastcall::code,
    luau_69_coverage::code,
    luau_70_capture::code,
    luau_71_subrk::code,
    luau_72_divrk::code,
    luau_73_fastcall1::code,
    luau_74_fastcall2::code,
    luau_75_fastcall2k::code,
    luau_76_forgprep::code,
    luau_77_jumpxeqknil::code,
    luau_78_jumpxeqkb::code,
    luau_79_jumpxeqkn::code,
    luau_80_jumpxeqks::code,
    luau_81_idiv::code,
    luau_82_idivk::code,
    luau_83_getudataks::code,
    luau_84_setudataks::code,
    luau_85_namecalludata::code,
    luau_86_newclassmember::code,
    luau_87_callfb::code,
    luau_88_cmpproto::code,
    luau_89_fastpcall::code,
    luau_90_newclass::code,
];

pub(super) fn luau(opcode: usize) -> &'static str {
    LUAU[opcode]()
}
