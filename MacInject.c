//12 - 1 - 2020

#include <stdio.h>
#include <stdlib.h>
#include <libproc.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach-o/dyld_images.h>
#include <dlfcn.h>
#include <pthread.h>




#pragma mark    -
#pragma mark    Function Forge




//In case you decide to do this on iOS?
kern_return_t mach_vm_allocate(vm_map_t target,
                               mach_vm_address_t *address,
                               mach_vm_size_t size,
                               int flags);
kern_return_t mach_vm_write(vm_map_t target_task,
                            mach_vm_address_t address,
                            vm_offset_t data,
                            mach_msg_type_number_t dataCnt);
kern_return_t mach_vm_protect(vm_map_t target_task,
                              mach_vm_address_t address,
                              mach_vm_size_t size,
                              boolean_t set_maximum,
                              vm_prot_t new_protection);
kern_return_t mach_vm_deallocate(vm_map_t target,
                                 mach_vm_address_t address,
                                 mach_vm_size_t size);




#pragma mark    -
#pragma mark    Utility Functions




void kr(int value) {
    if (value != KERN_SUCCESS) {
        printf("%s%s\n", "kern error: ", mach_error_string(value));
        exit(value);
    }
}



///Check if a module is loaded into the memory of a process.
bool check_image_exists(task_t task, const char* imagepath) {
    static bool image_exists = false;
    static mach_msg_type_number_t size;
    
    static mach_msg_type_number_t dataCnt;
    static vm_offset_t readData = 0;
    
    struct task_dyld_info dyld_info;
    mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
    task_info(task, TASK_DYLD_INFO, (task_info_t) &dyld_info, &count);
    size = sizeof(struct dyld_all_image_infos);
    mach_vm_read(task, dyld_info.all_image_info_addr, size, &readData, &dataCnt);
    unsigned char* data = (unsigned char*)readData;
    struct dyld_all_image_infos* infos = (struct dyld_all_image_infos*)data;
    size = sizeof(struct dyld_image_info)*infos->infoArrayCount;
    mach_vm_read(task, (mach_vm_address_t)infos->infoArray, size, &readData, &dataCnt);
    unsigned char* info_buf = (unsigned char*)readData;
    struct dyld_image_info* info = (struct dyld_image_info*)info_buf;
    
    for (int i = 0 ; i < (infos->infoArrayCount) ; i++) {
        size = PATH_MAX;
        mach_vm_read(task, (mach_vm_address_t)info[i].imageFilePath, size, &readData, &dataCnt);
        unsigned char* foundpath = (unsigned char*)readData;
        if (foundpath) {
            if (strcmp((const char*)(foundpath), imagepath) == 0) {
                image_exists = true;
            }
        }
    }
    return image_exists;
}


///Get the process ID of a process by its name.
int pid_by_name(const char* name) {
    static pid_t pids[4096];
    static int retpid = -1;
    int count = proc_listpids(PROC_ALL_PIDS, 0, pids, sizeof(pids));
    int proc_count = count/sizeof(pid_t);
    for (int i = 0; i < proc_count; i++) {
        struct proc_bsdinfo proc;
        int st = proc_pidinfo(pids[i], PROC_PIDTBSDINFO, 0, &proc, PROC_PIDTBSDINFO_SIZE);
        if (st == PROC_PIDTBSDINFO_SIZE) {
            if (strcmp(name, proc.pbi_name) == 0) {
                retpid = pids[i];
            }
        }
    }
    return retpid;
}




#pragma mark    -
#pragma mark    Shellcode




///Shellcode for the mach thread.
char mach_thread_code[] = {
#if defined (__x86_64__)
    0x55,                                           //push      rbp
    0x48, 0x89, 0xe5,                               //mov       rbp, rsp
    0x48, 0x89, 0xef,                               //mov       rdi, rbp
    0xff, 0xd0,                                     //call      rax
    0x48, 0xc7, 0xc0, 0x09, 0x03, 0x00, 0x00,       //mov       rax, 777
    0xe9, 0xfb, 0xff, 0xff, 0xff                    //jmp       -5
#endif
#if defined (__arm64__)
    0xff, 0x43, 0x00, 0xd1,                         //sub       sp, sp, 16
    0xe0, 0x23, 0x00, 0x91,                         //add       x0, sp, 8
    0x00, 0x01, 0x3f, 0xd6,                         //blr       x8
    0x28, 0x61, 0x80, 0xd2,                         //mov       x8, 777
    0x00, 0x00, 0x00, 0x14                          //b         0
#endif
};

///Shellcode for the posix thread.
char posix_thread_code[] = {
#if defined (__x86_64__)
    0x55,                                           //push      rbp
    0x48, 0x89, 0xe5,                               //mov       rbp, rsp
    0x48, 0x8b, 0x07,                               //mov       rax, [rdi]
    0x48, 0x8b, 0x7f, 0xf8,                         //mov       rdi, [rdi - 8]
    0xbe, 0x01, 0x00, 0x00, 0x00,                   //mov       esi, 1
    0xff, 0xd0,                                     //call      rax
    0xc9,                                           //leave
    0xc3                                            //ret
#endif
#if defined (__arm64__)
    0xff, 0x43, 0x00, 0xd1,                         //sub       sp, sp, 16
    0x08, 0x00, 0x40, 0xf9,                         //ldr       x8, [x0]
    0x00, 0x80, 0x5f, 0xf8,                         //ldr       x0, [x0, -8]
    0x21, 0x00, 0x80, 0xd2,                         //mov       x1, 1
    0x00, 0x01, 0x3f, 0xd6,                         //blr       x8
    0xff, 0x43, 0x00, 0x91,                         //add       sp, sp, 16
    0xc0, 0x03, 0x5f, 0xd6,                         //ret
    
#endif
};




///The function we will call through the mach thread.
int pthread_create_from_mach_thread(pthread_t *thread,
                                    const pthread_attr_t *attr,
                                    void *(*start_routine)(void *),
                                    void *arg);
//Function addresses. (At the global level to avoid a trace trap)
void* pthread_create_from_mach_thread_address = (void*)pthread_create_from_mach_thread;
void* dlopen_address = (void*)dlopen;




#pragma mark    -
#pragma mark    Inject




int pid = 0;
const char* lib_path;


///Inject a dynamic library into a process.
void inject() {
    ///The pointer size for the current architecture.
    static int ptr_size = sizeof(void*);
    ///The allocated stack size.
    static int stack_size = 1024;
    
    static int mach_code_size = (int)(sizeof(mach_thread_code));
    static int posix_code_size = (int)(sizeof(posix_thread_code));
    static vm_size_t path_length;
    path_length = strlen(lib_path);
    
    //Obtain the task port.
    static task_t task;
    kr(task_for_pid(mach_task_self_, pid, &task));
    
    //Check if the library was already loaded.
    //We don't really need this, but we can check if we even need to "inject" in the first place.
    if (check_image_exists(task, lib_path) == true) {
        printf("%s\n", "dylib is already loaded");
        return;
    }
    
    //Allocate the two instruction pointers.
    static mach_vm_address_t mach_code_mem;
    kr(mach_vm_allocate(task, &mach_code_mem, mach_code_size, VM_FLAGS_ANYWHERE));
    static mach_vm_address_t posix_code_mem;
    kr(mach_vm_allocate(task, &posix_code_mem, posix_code_size, VM_FLAGS_ANYWHERE));
    
    //Allocate the path variable and the stack.
    static mach_vm_address_t stack_mem;
    kr(mach_vm_allocate(task, &stack_mem, stack_size, VM_FLAGS_ANYWHERE));
    static mach_vm_address_t path_mem;
    kr(mach_vm_allocate(task, &path_mem, path_length, VM_FLAGS_ANYWHERE));
    
    //Allocate the pthread param block.
    ///This is the block of memory that will be passed to the pthread as a parameter. It's the pthread's job to "unpack" the block.
    /*
     The block will point to:
            + - - - - - - - - +
            | dlopen address  |             *(unsigned long*)(block)
            + - - - - - - - - +
            | pointer to path |             *(unsigned long*)(block - sizeof(void*))
            + - - - - - - - - +
     */

    static mach_vm_address_t posix_param_mem;
    kr(mach_vm_allocate(task, &posix_param_mem, (ptr_size * 2), VM_FLAGS_ANYWHERE));

    //Write the param block contents into memory. This block will be given to the pthread.
    kr(mach_vm_write(task, path_mem, (vm_offset_t)lib_path, (int)path_length));
    kr(mach_vm_write(task, posix_param_mem, (vm_offset_t)&dlopen_address, ptr_size));
    kr(mach_vm_write(task, posix_param_mem - ptr_size, (vm_offset_t)&path_mem, ptr_size));
    
    //Write to both instructions and mark them as executable.
    
    ///Do it for the mach thread instruction.
    kr(mach_vm_write(task, mach_code_mem, (vm_offset_t)&mach_thread_code, mach_code_size));
    kr(mach_vm_protect(task, mach_code_mem, mach_code_size, FALSE, VM_PROT_READ|VM_PROT_EXECUTE));
    
    ///Do it for the pthread instruction.
    kr(mach_vm_write(task, posix_code_mem, (vm_offset_t)&posix_thread_code, posix_code_size));
    kr(mach_vm_protect(task, posix_code_mem, posix_code_size, FALSE, VM_PROT_READ|VM_PROT_EXECUTE));
    
    //The state and state count for launching the thread and reading its registers.
    static mach_msg_type_number_t state_count;
    static mach_msg_type_number_t state;
    
#if defined (__x86_64__)
    static x86_thread_state64_t regs;
    //Set all the registers to 0 so we can avoid setting extra registers to 0.
    bzero(&regs, sizeof(regs));
    //Set the mach thread instruction pointer.
    regs.__rip = (__uint64_t)mach_code_mem;
    //Since the stack "grows" downwards, this is a usable stack pointer.
    regs.__rsp = (__uint64_t)(stack_mem + stack_size);
    //Set the function address, the 3rd parameter, and the 4th parameter.
    regs.__rax = (__uint64_t)pthread_create_from_mach_thread_address;
    regs.__rdx = (__uint64_t)posix_code_mem;
    regs.__rcx = (__uint64_t)posix_param_mem;
    
    state = x86_THREAD_STATE64;
    state_count = x86_THREAD_STATE64_COUNT;
#endif
#if defined (__arm64__)
    static arm_thread_state64_t regs;
    //Set all the registers to 0 so we can avoid setting extra registers to 0.
    bzero(&regs, sizeof(regs));
    //Set the mach thread instruction pointer.
    regs.__pc = (__uint64_t)mach_code_mem;
    //Since the stack "grows" downwards, this is a usable stack pointer.
    regs.__sp = (__uint64_t)(stack_mem + stack_size);
    //Set the function address, the 3rd parameter, and the 4th parameter.
    regs.__x[8] = (__uint64_t)pthread_create_from_mach_thread_address;
    regs.__x[2] = (__uint64_t)posix_code_mem;
    regs.__x[3] = (__uint64_t)posix_param_mem;
    
    state = ARM_THREAD_STATE64;
    state_count = ARM_THREAD_STATE64_COUNT;
#endif
    
    ///Initialize the thread.
    static thread_act_t thread;
    kr(thread_create_running(task, state, (thread_state_t)(&regs), state_count, &thread));
    
    ///Repeat check if a certain register has a certain value.
    for (;;) {
        static mach_msg_type_number_t sc;
        sc = state_count;
        kr(thread_get_state(thread, state, (thread_state_t)(&regs), &sc));
#if defined (__x86_64__)
        if (regs.__rax == 777) { break; }
#endif
#if defined (__arm64__)
        if (regs.__x[8] == 777) { break; }
#endif
    }
    
    ///Terminate the thread.
    kr(thread_suspend(thread));
    kr(thread_terminate(thread));
    
    ///Clean up.
    kr(mach_vm_deallocate(task, stack_mem, stack_size));
    kr(mach_vm_deallocate(task, mach_code_mem, mach_code_size));
    
    return;
}




#pragma mark    -
#pragma mark    int main()




char usage_msg[] =
"\n"
"MacInject: a macOS dylib injector by notahacker8 @ GitHub\n\n"
"usage: <target> <lib> <flags>\n"
"<target>: process id or name of the target\n"
"<lib>: path of library to inject\n"
"<flags>:\n"
"-name: use the name of the target\n"
"\n"
;


//In case something goes wrong and MacInject is consuming 99% CPU.
void* backup_exit() {
    sleep(1);
    exit(0);
    return NULL;
}



int main(int argc, char* argv[]) {
    if (argc > 2) {
        lib_path = argv[2];
        ///Check if the library even exists.
        static struct stat buf;
        if (stat(lib_path, &buf) != 0) {
            printf("%s\n", "library does not exist");
            return 0;
        }
        
        ///Check if a flag is used
        if (argc > 3) {
            if (strcmp(argv[3], "-name") == 0) {
                pid = pid_by_name(argv[1]);
            }
        } else {
            pid = atoi(argv[1]);
        }
    } else {
        printf("%s\n", usage_msg);
        return 0;
    }
    static pthread_t pt;
    pthread_create(&pt, NULL, backup_exit, NULL);
    inject();
    return 0;
}





