#include <common.h>

free_node* head;

typedef int lock_t;
lock_t kernel_lock;

#define OK 1//说明这把锁能用
#define FAILED 0//说明这把锁已经被占有了
#define Max_kalloc_size 16 * 1024 * 1024//大于16MiB的内存分配请求可以直接拒绝

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

static void *kalloc(size_t size) {
    if(size > Max_kalloc_size)return NULL;//直接拒绝
    else{//小内存分配,频繁的内存分配请求
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