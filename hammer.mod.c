#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0xfd039c20, __VMLINUX_SYMBOL_STR(module_layout) },
	{ 0xaafa12b7, __VMLINUX_SYMBOL_STR(iget_failed) },
	{ 0x3a9b8f1f, __VMLINUX_SYMBOL_STR(kmalloc_caches) },
	{ 0xd2b09ce5, __VMLINUX_SYMBOL_STR(__kmalloc) },
	{ 0x9255fe3c, __VMLINUX_SYMBOL_STR(__bread) },
	{ 0x754d539c, __VMLINUX_SYMBOL_STR(strlen) },
	{ 0x1ff6e92, __VMLINUX_SYMBOL_STR(kill_anon_super) },
	{ 0xc947da90, __VMLINUX_SYMBOL_STR(generic_file_open) },
	{ 0x20000329, __VMLINUX_SYMBOL_STR(simple_strtoul) },
	{ 0xf0af7a28, __VMLINUX_SYMBOL_STR(generic_file_aio_read) },
	{ 0x45a06a1e, __VMLINUX_SYMBOL_STR(mount_bdev) },
	{ 0x472ce0a, __VMLINUX_SYMBOL_STR(generic_file_aio_write) },
	{ 0xc499ae1e, __VMLINUX_SYMBOL_STR(kstrdup) },
	{ 0xe2d5255a, __VMLINUX_SYMBOL_STR(strcmp) },
	{ 0xfb578fc5, __VMLINUX_SYMBOL_STR(memset) },
	{ 0x11089ac7, __VMLINUX_SYMBOL_STR(_ctype) },
	{ 0x27e1a049, __VMLINUX_SYMBOL_STR(printk) },
	{ 0xa2f8b84d, __VMLINUX_SYMBOL_STR(d_rehash) },
	{ 0x449ad0a7, __VMLINUX_SYMBOL_STR(memcmp) },
	{ 0x7c1372e8, __VMLINUX_SYMBOL_STR(panic) },
	{ 0x5792f848, __VMLINUX_SYMBOL_STR(strlcpy) },
	{ 0x4afcb0e8, __VMLINUX_SYMBOL_STR(unlock_page) },
	{ 0xecd4272d, __VMLINUX_SYMBOL_STR(__brelse) },
	{ 0xf0fdf6cb, __VMLINUX_SYMBOL_STR(__stack_chk_fail) },
	{ 0xa202a8e5, __VMLINUX_SYMBOL_STR(kmalloc_order_trace) },
	{ 0x11f3de9d, __VMLINUX_SYMBOL_STR(do_sync_read) },
	{ 0xbdfb6dbb, __VMLINUX_SYMBOL_STR(__fentry__) },
	{ 0x75087046, __VMLINUX_SYMBOL_STR(kmem_cache_alloc_trace) },
	{ 0xc007064d, __VMLINUX_SYMBOL_STR(register_filesystem) },
	{ 0x4f68e5c9, __VMLINUX_SYMBOL_STR(do_gettimeofday) },
	{ 0xd0a5cea0, __VMLINUX_SYMBOL_STR(iput) },
	{ 0x37a0cba, __VMLINUX_SYMBOL_STR(kfree) },
	{ 0x69acdf38, __VMLINUX_SYMBOL_STR(memcpy) },
	{ 0xd751a5f8, __VMLINUX_SYMBOL_STR(sb_set_blocksize) },
	{ 0x713e85a7, __VMLINUX_SYMBOL_STR(unregister_filesystem) },
	{ 0x28318305, __VMLINUX_SYMBOL_STR(snprintf) },
	{ 0x3a5c0069, __VMLINUX_SYMBOL_STR(new_inode) },
	{ 0x169f2cc7, __VMLINUX_SYMBOL_STR(d_instantiate) },
	{ 0xd382e337, __VMLINUX_SYMBOL_STR(generic_fillattr) },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";

