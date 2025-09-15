
//7/15/23.

#include <stdio.h>
#include <stdlib.h>
#include <libproc.h>
#include <mach/mach.h>
#include <mach-o/loader.h>
#include <mach/mach_vm.h>
#include <mach/arm64/asm.h>
#include <mach-o/dyld.h>
#include <mach/arm/thread_state.h>
#include <mach/arm/thread_status.h>
#include <mach/thread_state.h>
#include <mach/thread_status.h>
#include <mach/mach_init.h>
#include <mach/thread_policy.h>
#include <mach-o/dyld_images.h>
#include <mach/vm_region.h>
#include <mach/arm/_structs.h>
#include <mach-o/nlist.h>
#include <math.h>
#include <tgmath.h>
#include <dlfcn.h>
#include <math.h>
#include <pthread.h>
#include <pthread/sched.h>
#include <sys/ptrace.h>


#define ARM_THREAD_STATE64 6
typedef struct
{
    __uint64_t __x[29]; /* General purpose registers x0-x28 */
    __uint64_t __fp;    /* Frame pointer x29 */
    __uint64_t __lr;    /* Link register x30 */
    __uint64_t __sp;    /* Stack pointer x31 */
    __uint64_t __pc;    /* Program counter */
    __uint32_t __cpsr;  /* Current program status register */
    __uint32_t __pad;   /* Same size for 32-bit or 64-bit clients */
}
__arm_thread_state64_t;
#define ARM_THREAD_STATE64_COUNT ((mach_msg_type_number_t) \
    (sizeof (__arm_thread_state64_t)/sizeof(uint32_t)))




///The function we will call through the mach thread.
int pthread_create_from_mach_thread(pthread_t *thread,
                                    const pthread_attr_t *attr,
                                    void *(*start_routine)(void *),
                                    void *arg);




#define kr(value) if (value != KERN_SUCCESS)\
{\
    printf("kern error: %s, line %d\n", mach_error_string(value), __LINE__);\
    exit(value);\
}

vm_address_t task_get_image_address_by_path(const task_t task,
                                            const char* image_path)
{
    vm_address_t image_address = 0;
    
    struct task_dyld_info dyld_info;
    mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
    kern_return_t kr = task_info(task, TASK_DYLD_INFO, (task_info_t)&dyld_info, &count);
    static mach_msg_type_number_t data_cnt = 0;
    if (kr == KERN_SUCCESS)
    {
        struct dyld_all_image_infos* infos;
        kern_return_t kr = vm_read(task, dyld_info.all_image_info_addr, sizeof(struct dyld_all_image_infos), (vm_address_t*)&infos, &data_cnt);
        if (kr == KERN_SUCCESS)
        {
            vm_address_t info_array_addr = (vm_address_t)infos -> infoArray;
            int info_count = infos -> infoArrayCount;
            for (int i = 0 ; i < info_count ; i++)
            {
                vm_address_t dii_ptr = info_array_addr + (i * sizeof(struct dyld_image_info));
                struct dyld_image_info* dii;
                kern_return_t kr = vm_read(task, dii_ptr, sizeof(struct dyld_image_info), (vm_address_t*)&dii, &data_cnt);
                if (kr == KERN_SUCCESS)
                {
                    vm_address_t img_file_path_ptr = (vm_address_t)(dii -> imageFilePath);
                    vm_address_t img_ld_address = (vm_address_t)(dii -> imageLoadAddress);
                    char* img_file_path;
                    kern_return_t kr = vm_read(task, img_file_path_ptr, PATH_MAX, (vm_address_t*)&img_file_path, &data_cnt);
                    if (kr == KERN_SUCCESS)
                    {
                        if (strcmp(image_path, img_file_path) == 0)
                        {
                            image_address = img_ld_address;
                        }
                        vm_deallocate(mach_task_self_, (vm_address_t)img_file_path, PATH_MAX);
                    }
                    vm_deallocate(mach_task_self_, (vm_address_t)dii, sizeof(struct dyld_image_info));
                }
            }
            vm_deallocate(mach_task_self_, (vm_address_t)infos, sizeof(struct dyld_all_image_infos));
        }
    }
    
    return image_address;
}





#pragma mark    - Shellcode -






///Shellcode for the mach thread.
unsigned char mach_thread_code[] =
{
    "\x80\x00\x3f\xd6" //blr x4
    "\x00\x00\x00\x14" // b 0
};


#define MACH_CODE_SIZE sizeof(mach_thread_code)
#define STACK_SIZE 32 * 32




/*
 IMPORTANT NOTE: This won't work on other processes when testing in Xcode. It will only work if both processes are not in Xcode.
 
 Basically, we can make an inject a dylib into another process by creating a thread that calls dlopen() and loads our library.
 However, we must use pthread_create_from_mach_thread() to call dlopen(), since mach threads apparently can't.
 You can read more about code injection here: https://knight.sc/malware/2019/03/15/code-injection-on-macos.html
 
 */



int main(int argc, const char * argv[]) {
    // insert code here...
    if (argc < 3)
    {
        printf("usage: /Path/to/MacInject [dylib path] [pid]\n");
        exit(EXIT_FAILURE);
    }
    int pid = atoi(argv[2]);
    const char* path = argv[1];
    task_t task;
    kr(task_for_pid(mach_task_self_, pid, &task));
    
    if (task_get_image_address_by_path(task, path))
    {
        printf("dylib/image already loaded in process\n");
        exit(EXIT_FAILURE);
    }
    
    vm_address_t remote_mach_code = 0;
    vm_address_t remote_stack = 0;
    vm_address_t remote_pthread_mem = 0;
    vm_address_t remote_path = 0;
    
    kr(vm_allocate(task, &remote_mach_code, MACH_CODE_SIZE, VM_FLAGS_ANYWHERE));
    kr(vm_allocate(task, &remote_stack, STACK_SIZE, VM_FLAGS_ANYWHERE));
    kr(vm_allocate(task, &remote_pthread_mem, 8, VM_FLAGS_ANYWHERE));
    kr(vm_allocate(task, &remote_path, strlen(path), VM_FLAGS_ANYWHERE));
    
    kr(vm_write(task, remote_path, (vm_address_t)path, (int)strlen(path)));
    kr(vm_write(task, remote_mach_code, (vm_address_t)mach_thread_code, MACH_CODE_SIZE));
    kr(vm_protect(task, remote_mach_code, MACH_CODE_SIZE, FALSE, VM_PROT_READ|VM_PROT_EXECUTE));

    
    __arm_thread_state64_t regs;
    bzero(&regs, sizeof(regs));
    regs.__pc = remote_mach_code;
    regs.__sp = remote_stack - 128;
    
    regs.__x[4] = (vm_address_t)pthread_create_from_mach_thread;
    regs.__x[0] = remote_pthread_mem;
    regs.__x[1] = 0;
    regs.__x[2] = (vm_address_t)dlopen;
    regs.__x[3] = remote_path;
    
    thread_act_t remote_thread;
    kr(thread_create_running(task, ARM_THREAD_STATE64, (thread_state_t)&regs, ARM_THREAD_STATE64_COUNT, &remote_thread));
    sleep(1);
    kr(thread_terminate(remote_thread));
    return 0;
}
