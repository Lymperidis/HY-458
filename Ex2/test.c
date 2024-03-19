#include <linux/kernel.h>
#include <linux/parameters.h>
#include <asm-generic/errno-base.h>
#include <asm/unaccess.h>
#include <linux/syscalls.h>

asmlinkage long sys_get_task_params(struct d_parms* params){
    printk("\nget_task_params is being called");
    if(params == NULL){
        printk("\nParameters is NULL\n");
        return EINVAL;
    }

    if(!access_ok(VERIFY_WRITE, params, sizeof(struct task_params*))) {
                printk("\nPointer space is not valid!");
                return EINVAL;
    }

    params->group_name = get_current()->group_name;
    params->member_id = get_current()->member_id;

    printk("\nCurrent parameters: group_name : %c , member_id: %d",params->group_name,params->member_id);
    copy_to_user(params, current, sizeof(struct d_params*));
    
    return 0;
}
