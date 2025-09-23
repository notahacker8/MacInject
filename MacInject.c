//12 - 1 - 2020

#include <stdio.h>
#include <stdlib.h>
#include <libproc.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach-o/dyld_images.h>
#include <dlfcn.h>
#include <pthread.h>



#define PTR_SIZE sizeof(void*)
#define STACK_SIZE 1024




#pragma mark    -
#pragma mark    Symbol Declaration




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

///The function we will call through the mach thread.
int pthread_create_from_mach_thread(pthread_t *thread,
                                    const pthread_attr_t *attr,
                                    void *(*start_routine)(void *),
                                    void *arg);




#pragma mark    -
#pragma mark    Utility Functions




#define kr(value) if (value != KERN_SUCCESS)\
{\
    printf("kern error: %s, line %d\n", mach_error_string(value), __LINE__);\
    exit(value);\
}



///Check if a module is loaded into the memory of a process.
bool check_image_exists(const task_t task,
                        const char* imagepath)
{
    bool image_exists = false;
    mach_msg_type_number_t size = 0;
    
    mach_msg_type_number_t dataCnt = 0;
    vm_offset_t readData = 0;
    
    struct task_dyld_info dyld_info;
    mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
    task_info(task, TASK_DYLD_INFO, (task_info_t)&dyld_info, &count);
    size = sizeof(struct dyld_all_image_infos);
    mach_vm_read(task, dyld_info.all_image_info_addr, size, &readData, &dataCnt);
    unsigned char* data = (unsigned char*)readData;
    struct dyld_all_image_infos* infos = (struct dyld_all_image_infos*)data;
    size = sizeof(struct dyld_image_info)*(infos -> infoArrayCount);
    mach_vm_read(task, (mach_vm_address_t)infos -> infoArray, size, &readData, &dataCnt);
    unsigned char* info_buf = (unsigned char*)readData;
    struct dyld_image_info* info = (struct dyld_image_info*)info_buf;
    
    for (int i = 0 ; i < (infos -> infoArrayCount) ; i++)
    {
        size = PATH_MAX;
        mach_vm_read(task, (mach_vm_address_t)info[i].imageFilePath, size, &readData, &dataCnt);
        unsigned char* foundpath = (unsigned char*)readData;
        if (foundpath)
        {
            if (strcmp((const char*)(foundpath), imagepath) == 0)
            {
                image_exists = true;
            }
        }
    }
    return image_exists;
}


///Get the process ID of a process by its name.
const pid_t pid_by_name(const char* name)
{
    static pid_t pids[4096];
    int retpid = -1;
    const int count = proc_listpids(PROC_ALL_PIDS, 0, pids, sizeof(pids));
    const int proc_count = count/sizeof(pid_t);
    for (int i = 0; i < proc_count; i++)
    {
        struct proc_bsdinfo proc;
        const int st = proc_pidinfo(pids[i], PROC_PIDTBSDINFO, 0, &proc, PROC_PIDTBSDINFO_SIZE);
        if (st == PROC_PIDTBSDINFO_SIZE)
        {
            if (strcmp(name, proc.pbi_name) == 0)
            {
                retpid = pids[i];
            }
        }
    }
    return retpid;
}




#pragma mark    -
#pragma mark    Shellcode




///Shellcode for the mach thread.
static const unsigned char mach_thread_code[] =
{
    0x55,                                           //push      rbp
    0x48, 0x89, 0xe5,                               //mov       rbp, rsp
    0x48, 0x89, 0xef,                               //mov       rdi, rbp
    0xff, 0xd0,                                     //call      rax
    0x48, 0xc7, 0xc0, 0x09, 0x03, 0x00, 0x00,       //mov       rax, 777
    0xe9, 0xfb, 0xff, 0xff, 0xff                    //jmp       -5
};

///Shellcode for the posix thread.
static const unsigned char posix_thread_code[] =
{
    0x55,                                           //push      rbp
    0x48, 0x89, 0xe5,                               //mov       rbp, rsp
    0x48, 0x8b, 0x07,                               //mov       rax, [rdi]
    0x48, 0x8b, 0x7f, 0xf8,                         //mov       rdi, [rdi - 8]
    0xbe, 0x01, 0x00, 0x00, 0x00,                   //mov       esi, 1
    0xff, 0xd0,                                     //call      rax
    0xc9,                                           //leave
    0xc3                                            //ret
};


#define MACH_CODE_SIZE sizeof(mach_thread_code)
#define POSIX_CODE_SIZE sizeof(posix_thread_code)




#pragma mark    -
#pragma mark    Inject




///Inject a dynamic library into a process.
void inject(const pid_t process_id,
            const char* dylib_path)
{
    
    //Function addresses.
    const static void* pthread_create_from_mach_thread_address =
    (const void*)pthread_create_from_mach_thread;
    
    const static void* dlopen_address = (const void*)dlopen;
    
    vm_size_t path_length = strlen(dylib_path);
    
    //Obtain the task port.
    task_t task;
    kr(task_for_pid(mach_task_self_, process_id, &task));
    
    //Check if the library was already loaded.
    //We don't really need this, but we can check if we even need to "inject" in the first place.
    if (check_image_exists(task, dylib_path) == true)
    {
        printf("%s\n", "dylib is already loaded");
        return;
    }
    
    //Allocate the two instruction pointers.
    mach_vm_address_t mach_code_mem = 0;
    kr(mach_vm_allocate(task, &mach_code_mem, MACH_CODE_SIZE, VM_FLAGS_ANYWHERE));
    
    mach_vm_address_t posix_code_mem = 0;
    kr(mach_vm_allocate(task, &posix_code_mem, MACH_CODE_SIZE, VM_FLAGS_ANYWHERE));
    
    
    //Allocate the path variable and the stack.
    mach_vm_address_t stack_mem = 0;
    kr(mach_vm_allocate(task, &stack_mem, STACK_SIZE, VM_FLAGS_ANYWHERE));
    
    mach_vm_address_t path_mem = 0;
    kr(mach_vm_allocate(task, &path_mem, path_length, VM_FLAGS_ANYWHERE));
    
    
    //Allocate the pthread parameter array.
    mach_vm_address_t posix_param_mem = 0;
    kr(mach_vm_allocate(task, &posix_param_mem, (PTR_SIZE * 2), VM_FLAGS_ANYWHERE));

    //Write the path into memory.
    kr(mach_vm_write(task, path_mem, (vm_offset_t)dylib_path, (int)path_length));
    
    //Write the parameter array contents into memory. This array will be the pthread's parameter.
    
    //The address of dlopen() is the first parameter.
    kr(mach_vm_write(task, posix_param_mem, (vm_offset_t)&dlopen_address, PTR_SIZE));
    
    //The pointer to the dylib path is the second parameter.
    kr(mach_vm_write(task, (posix_param_mem - PTR_SIZE), (vm_offset_t)&path_mem, PTR_SIZE));
    
    
    
    //Write to both instructions, and mark them as readable, writable, and executable.
    
    //Do it for the mach thread instruction.
    kr(mach_vm_write(task, mach_code_mem, (vm_offset_t)&mach_thread_code, MACH_CODE_SIZE));
    kr(mach_vm_protect(task, mach_code_mem, MACH_CODE_SIZE, FALSE, VM_PROT_ALL));
    
    //Do it for the pthread instruction.
    kr(mach_vm_write(task, posix_code_mem, (vm_offset_t)&posix_thread_code, POSIX_CODE_SIZE));
    kr(mach_vm_protect(task, posix_code_mem, POSIX_CODE_SIZE, FALSE, VM_PROT_ALL));
    
    
    
    //The state and state count for launching the thread and reading its registers.
    mach_msg_type_number_t state_count = x86_THREAD_STATE64_COUNT;
    mach_msg_type_number_t state = x86_THREAD_STATE64;
    
    //Set all the registers to 0 so we can avoid setting extra registers to 0.
    x86_thread_state64_t regs;
    bzero(&regs, sizeof(regs));
    
    //Set the mach thread instruction pointer.
    regs.__rip = (__uint64_t)mach_code_mem;
    
    //Since the stack "grows" downwards, this is a usable stack pointer.
    regs.__rsp = (__uint64_t)(stack_mem + STACK_SIZE);
    
    //Set the function address, the 3rd parameter, and the 4th parameter.
    regs.__rax = (__uint64_t)pthread_create_from_mach_thread_address;
    regs.__rdx = (__uint64_t)posix_code_mem;
    regs.__rcx = (__uint64_t)posix_param_mem;

    
    
    //Initialize the thread.
    thread_act_t thread;
    kr(thread_create_running(task, state, (thread_state_t)(&regs), state_count, &thread));
    
    //Repeat check if a certain register has a certain value.
    for (;;)
    {
        mach_msg_type_number_t sc = state_count;
        kr(thread_get_state(thread, state, (thread_state_t)(&regs), &sc));
        if (regs.__rax == 777)
        {
            break;
        }
        usleep(10000);
    }
    
    ///Terminate the thread.
    kr(thread_suspend(thread));
    kr(thread_terminate(thread));
    
    ///Clean up.
    kr(mach_vm_deallocate(task, stack_mem, STACK_SIZE));
    kr(mach_vm_deallocate(task, mach_code_mem, MACH_CODE_SIZE));
    
    return;
}




#pragma mark    -
#pragma mark    int main()




//In case something goes wrong and MacInject is consuming a ton of CPU.
void* backup_exit()
{
    sleep(1);
    exit(0);
    return NULL;
}



int main(const int argc,
         const char* argv[])
{
    
    const static unsigned char usage_msg[] =
    "\n"
    "MacInject: a macOS dylib injector by notahacker8 @ GitHub\n\n"
    "usage: <target> <dylib> <flags>\n"
    "<target>: process id or name of the target\n"
    "<dylib>: path of dynamic library to inject\n"
    "<flags>: see options below\n"
    "\t-name (option): use the name of the target\n"
    "(root is not required)"
    "\n"
    ;
    
    static const char* dylib_path = NULL;
    static pid_t process_id = -1;
    
    if (argc > 2)
    {
        dylib_path = argv[2];
        ///Check if the library even exists.
        struct stat buf;
        if (stat(dylib_path, &buf) != 0)
        {
            printf("%s\n", "library does not exist");
            return 0;
        }
        
        ///Check if a flag is used.
        if (argc > 3)
        {
            if (strcmp(argv[3], "-name") == 0)
            {
                process_id = pid_by_name(argv[1]);
            }
        }
        else
        {
            process_id = atoi(argv[1]);
        }
    }
    else
    {
        printf("%s\n", usage_msg);
        return 0;
    }
    pthread_t pthread;
    pthread_create(&pthread, NULL, backup_exit, NULL);
    inject(process_id, dylib_path);
    return 0;
}






