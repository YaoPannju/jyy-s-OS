#include <common.h>

free_node* head;

typedef int lock_t;
lock_t kernel_lock;

#define OK 1//说明这把锁能用
#define FAILED 0//说明这把锁已经被占有了
#define Max_kalloc_size 16 * 1024 * 1024//大于16MiB的内存分配请求可以直接拒绝

cpu_pagelist cpu_plists[8];

//my implementation of lock, spin_lock()
void lock(lock_t* my_lock){
    while(atomic_xchg(my_lock, FAILED) != OK)
    {
        ;
    }
    assert(*my_lock == FAILED);
}

void unlock(lock_t* my_lock){
    atomic_xchg(my_lock, OK);
}

void lock_init(lock_t* my_lock){
    *my_lock = OK;
}

void* huge_memory_alloc(size_t size){
    size_t new_size = 4 * 1024;
    while(new_size < size)new_size = new_size<<1;
    size = new_size;
    //一把大锁保平安
    lock(&kernel_lock);
    free_node* h = head;
    free_node* new_node = NULL;
    while(h != NULL){//尽量都往后找
        assert(h->size >= sizeof(free_node));
        if(h->size >= size + sizeof(occupied_node) + sizeof(free_node)){
            new_node = h;
        }
        h = h->next;
    }
    if(new_node == NULL){
        unlock(&kernel_lock);
        return NULL;
    }
    void* ret = (void*)new_node + new_node->size - size;
    if((uintptr_t)ret % size == 0){
        new_node->size -= size + sizeof(occupied_node);
        occupied_node* ocp_node = (occupied_node*)((void*)ret - sizeof(occupied_node));
        ocp_node->prev = new_node;
        ocp_node->size = size;
        unlock(&kernel_lock);
        return ret;
    }
    else{
        size_t num = (uintptr_t)ret / size;
        void* new_ret = (void*)(num * size);
        if((uintptr_t)new_ret - (uintptr_t)new_node < sizeof(free_node) + sizeof(occupied_node)){
            unlock(&kernel_lock);
            return NULL;
        }
        occupied_node* ocp_node = (occupied_node*)((void*)new_ret - sizeof(occupied_node));
        size_t space_used = (uintptr_t)new_node + new_node->size - (uintptr_t)new_ret;
        ocp_node->size = space_used;
        ocp_node->prev = new_node;
        new_node->size -= space_used + sizeof(occupied_node);
        unlock(&kernel_lock);
        return new_ret;
    }
}

void* huge_memory_alloc1(size_t size){
    if(size < 32)size = 32;
    else{
        size_t new_size = 32;
        while(new_size < size)new_size = new_size<<1;
        size = new_size;
    }
    //一把大锁保平安
    lock(&kernel_lock);
    free_node* h = head;
    free_node* new_node = NULL;
    while(h != NULL){//尽量都往后找
        assert(h->size >= sizeof(free_node));
        if(h->size >= size + sizeof(occupied_node) + sizeof(free_node)){
            new_node = h;
        }
        h = h->next;
    }
    if(new_node == NULL){
        unlock(&kernel_lock);
        return NULL;
    }
    void* ret = (void*)new_node + new_node->size - size;
    if((uintptr_t)ret % size == 0){
        new_node->size -= size + sizeof(occupied_node);
        occupied_node* ocp_node = (occupied_node*)((void*)ret - sizeof(occupied_node));
        ocp_node->prev = new_node;
        ocp_node->size = size;
        unlock(&kernel_lock);
        return ret;
    }
    else{
        size_t num = (uintptr_t)ret / size;
        void* new_ret = (void*)(num * size);
        if((uintptr_t)new_ret - (uintptr_t)new_node < sizeof(free_node) + sizeof(occupied_node)){
            unlock(&kernel_lock);
            return NULL;
        }
        occupied_node* ocp_node = (occupied_node*)((void*)new_ret - sizeof(occupied_node));
        size_t space_used = (uintptr_t)new_node + new_node->size - (uintptr_t)new_ret;
        ocp_node->size = space_used;
        ocp_node->prev = new_node;
        new_node->size -= space_used + sizeof(occupied_node);
        unlock(&kernel_lock);
        return new_ret;
    }
}

void* Page_Alloc(int cpuno){
    lock(&(cpu_plists[cpuno].cpu_lock));
    struct cpu_pageheader* cpu_page = cpu_plists[cpuno].page_header;
    if(cpu_page == NULL){
    	//printf("Here!\n");
        cpu_page = (cpu_pageheader*)huge_memory_alloc(256 * 1024);
        if(cpu_page == NULL){
            unlock(&(cpu_plists[cpuno].cpu_lock));
            return NULL;
        }
        cpu_plists[cpuno].page_header = cpu_page;
        occupied_node* ocp_node = (occupied_node*)((void*)cpu_page - sizeof(occupied_node));
        cpu_page->size = ocp_node->size;
        cpu_page->space_left = cpu_page->size / (4 * 1024) - 1;
        cpu_page->cpu_num = cpuno;
        cpu_page->next = NULL;
        //进行处理
        //printf("cpu %d has space %d left!\n", cpu_page->cpu_num, cpu_page->space_left);
        cpu_page->space_left -= 1;
        unlock(&(cpu_plists[cpuno].cpu_lock));
        return (void*)cpu_page + (cpu_page->size / (4 * 1024) - 1 - cpu_page->space_left) * 4 * 1024;
    }
    else{
        while(cpu_page->next != NULL){
            cpu_page = cpu_page->next;
        }
        assert(cpu_page->next == NULL);
        if(cpu_page->space_left == 0){
            struct cpu_pageheader* next_page = (cpu_pageheader*)huge_memory_alloc(256 * 1024);
            cpu_page->next = next_page;
            cpu_page = next_page;
            if(cpu_page == NULL){
                unlock(&(cpu_plists[cpuno].cpu_lock));
                return NULL;
            }
            occupied_node* ocp_node = (occupied_node*)((void*)cpu_page - sizeof(occupied_node));
            cpu_page->size = ocp_node->size;
            //printf("Allocated Size = %d\n", cpu_page->size);
            cpu_page->space_left = cpu_page->size / (4 * 1024) - 1;
            cpu_page->cpu_num = cpuno;
            cpu_page->next = NULL;
            //printf("cpu %d has space %d left!\n", cpu_page->cpu_num, cpu_page->space_left);
            //进行处理
            cpu_page->space_left -= 1;
            //assert(cpu_page->space_left == 254);
            unlock(&(cpu_plists[cpuno].cpu_lock));
            return (void*)cpu_page + (cpu_page->size / (4 * 1024) - 1 - cpu_page->space_left) * 4 * 1024;
            //return huge_memory_alloc(4 * 1024);
        }
        else{
            //assert(cpu_page->space_left <= 254);
            cpu_page->space_left = cpu_page->space_left - 1;
            //printf("cpu %d has space %d left!\n", cpu_page->cpu_num, cpu_page->space_left);
            //assert(cpu_page->space_left >= 0);
            void* ret = (void*)cpu_page + (cpu_page->size / (4 * 1024) - 1 - cpu_page->space_left) * 4 * 1024;
            //if(ret > (void*)cpu_page + 255 * 4 * 1024)ret = huge_memory_alloc(4 * 1024);
            unlock(&(cpu_plists[cpuno].cpu_lock));
            return ret;
        }
    }
}

void* frequent_alloc(int cpuno, int size, struct cpu_pageheader* my_head){
    lock(&(cpu_plists[cpuno].cpu_lock));
    struct cpu_pageheader* cpu_page = my_head;
    if(cpu_page == NULL && (size == 32 || size == 64 || size == 128)){
        //assert(size == 32 || size == 64 || size == 128);
        //printf("Here\n");
        cpu_page = (cpu_pageheader*)huge_memory_alloc(512 * 1024);
        if(cpu_page == NULL){
            unlock(&(cpu_plists[cpuno].cpu_lock));
            return NULL;
        }
        occupied_node* ocp_node = (occupied_node*)((void*)cpu_page - sizeof(occupied_node));
        cpu_page->size = ocp_node->size;
        cpu_page->space_left = cpu_page->size / size - 1;
        cpu_page->cpu_num = cpuno;
        cpu_page->next = NULL;
        //进行处理
        cpu_page->space_left -= 1;
        //printf("cpu %d has space %d left!\n", cpu_page->cpu_num, cpu_page->space_left);
        if(size == 32)cpu_plists[cpuno].page_header32 = cpu_page;
        else if(size == 64)cpu_plists[cpuno].page_header64 = cpu_page;
        else if(size == 128)cpu_plists[cpuno].page_header128 = cpu_page;
        void* ret = (void*)cpu_page + size;
        unlock(&(cpu_plists[cpuno].cpu_lock));
        return ret;
    }
    else if(cpu_page == NULL){
        assert(!(size == 32 || size == 64 || size == 128));
        unlock(&(cpu_plists[cpuno].cpu_lock));
        return huge_memory_alloc1(size);
    }
    else{
        assert(size == 32 || size == 64 || size == 128);
        //unlock(&(cpu_plists[cpuno].cpu_lock));
        //return huge_memory_alloc1(size);
        while(cpu_page->next != NULL){
            cpu_page = cpu_page->next;
        }
        assert(cpu_page->next == NULL);
        if(cpu_page->space_left == 0){
            struct cpu_pageheader* next_page = (cpu_pageheader*)huge_memory_alloc(512 * 1024);
            cpu_page->next = next_page;
            cpu_page = next_page;
            if(cpu_page == NULL){
                unlock(&(cpu_plists[cpuno].cpu_lock));
                return NULL;
            }
            occupied_node* ocp_node = (occupied_node*)((void*)cpu_page - sizeof(occupied_node));
            cpu_page->size = ocp_node->size;
            //printf("Allocated Size = %d\n", cpu_page->size);
            cpu_page->space_left = cpu_page->size / size - 1;
            cpu_page->cpu_num = cpuno;
            cpu_page->next = NULL;
            //printf("cpu %d has space %d left!\n", cpu_page->cpu_num, cpu_page->space_left);
            //进行处理
            cpu_page->space_left -= 1;
            //assert(cpu_page->space_left == 254);
            unlock(&(cpu_plists[cpuno].cpu_lock));
            return (void*)cpu_page + (cpu_page->size / size - 1 - cpu_page->space_left) * size;
            //return huge_memory_alloc(4 * 1024);
        }
        else{
            //assert(cpu_page->space_left <= 254);
            cpu_page->space_left = cpu_page->space_left - 1;
            //printf("cpu %d has space %d left!\n", cpu_page->cpu_num, cpu_page->space_left);
            //assert(cpu_page->space_left >= 0);
            void* ret = (void*)cpu_page + (cpu_page->size / size - 1 - cpu_page->space_left) * size;
            //if(ret > (void*)cpu_page + 255 * 4 * 1024)ret = huge_memory_alloc(4 * 1024);
            unlock(&(cpu_plists[cpuno].cpu_lock));
            return ret;
            //return huge_memory_alloc(4 * 1024);
        }
    }
}

static void *kalloc(size_t size) {
    if(size > Max_kalloc_size)return NULL;//直接拒绝
    else if(size > 4 * 1024){
    	return huge_memory_alloc(size);
    }
    else if(size == 4 * 1024){
        int cpuno = cpu_current();
        return Page_Alloc(cpuno);
    }
    else{//小内存分配,频繁的内存分配请求
        //内存标准化处理
        if(size <= 32)size = 32;
        else{
            size_t my_size = 32;
            while(my_size < size){
                my_size *= 2;
            }
            size = my_size;
        }
        //获得对应的要使用/更新的页表头
        cpu_pageheader* cpu_page = NULL;
        int cpuno = cpu_current();
        switch(size){
            case 32:
                cpu_page = cpu_plists[cpuno].page_header32;
                break;
            case 64:
                cpu_page = cpu_plists[cpuno].page_header64;
                break;
            case 128:
                cpu_page = cpu_plists[cpuno].page_header128;
                break;
            default:break;
        }
        return frequent_alloc(cpuno, size, cpu_page);
    }
}

static void kfree(void *ptr) {
    // TODO
    // You can add more .c files to the repo.
}

static void pmm_init() {
    uintptr_t pmsize = (
        (uintptr_t)heap.end
        - (uintptr_t)heap.start
    );

    printf(
        "Got %d MiB heap: [%p, %p)\n",
        pmsize >> 20, heap.start, heap.end
    );

    for(int i = 0; i <= 7; i++){
        cpu_plists[i].page_header = NULL;
        cpu_plists[i].page_header32 = NULL;
        cpu_plists[i].page_header64 = NULL;
        cpu_plists[i].page_header128 = NULL;
        cpu_plists[i].other_header = NULL;
        lock_init(&(cpu_plists[i].cpu_lock));
    }

    head = (free_node*)heap.start;
    head->size = pmsize;
    head->next = NULL;
    head->prev = NULL;
    lock_init(&kernel_lock);
}

MODULE_DEF(pmm) = {
    .init  = pmm_init,
    .alloc = kalloc,
    .free  = kfree,
};