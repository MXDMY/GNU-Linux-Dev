
#include <linux/module.h> // 包含内核模块信息声明的相关函数
#include <linux/init.h>   // 包含了 module_init()和 module_exit()函数的声明
#include <linux/kernel.h> // 包含内核提供的各种函数，如 printk

static int __init ex_chrdev_init(void)
{
    printk(KERN_INFO "%s...\n", __func__);
    return 0;
}

static void __exit ex_chrdev_exit(void)
{
    printk(KERN_INFO "%s...\n", __func__);
}

module_init(ex_chrdev_init);
module_exit(ex_chrdev_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("bj");
MODULE_DESCRIPTION("Shows roughly what a character device driver module looks like");
MODULE_ALIAS("example_character_device");

