//
//  NULLGuard.c
//  NULLGuard
//
//  Created by qwertyoruiop on 16/08/15.
//  Copyright (c) 2015 kim jong cracks. All rights reserved.
//
#include <sys/types.h>
#include <sys/kernel.h>
#include <sys/kauth.h>
#include <mach/mach_types.h>
#define CONFIG_MACF 1
#include <security/mac_framework.h>
#include <security/mac.h>
#include <security/mac_policy.h>
#include <sys/vnode.h>
#include <vfs/vfs_support.h>
#include <mach-o/loader.h>
#include <mach-o/fat.h>

// thanks to fG!

static kern_return_t
get_mach_header(void *buffer, vnode_t kernel_vnode, int offset)
{
    int error = 0;
    
    uio_t uio = NULL;
    uio = uio_create(1, offset, UIO_SYSSPACE, UIO_READ);
    if (uio == NULL) return KERN_FAILURE;
    error = uio_addiov(uio, CAST_USER_ADDR_T(buffer), PAGE_SIZE_64*4);
    if (error) return error;
    error = VNOP_READ(kernel_vnode, uio, 0, vfs_context_create(NULL));
    if (error) return error;
    else if (uio_resid(uio)) return EINVAL;
    uio_free(uio);
    return KERN_SUCCESS;
}

extern void IOLog(char* fmt, ...);
kern_return_t NULLGuard_start(kmod_info_t * ki, void *d);
kern_return_t NULLGuard_stop(kmod_info_t *ki, void *d);

int nullguard_checkmh(struct mach_header* mh) {
    if (mh->magic == MH_MAGIC) {
        // only 32 bit processes can lack PAGEZERO when uid != 0
        struct load_command *loadCmd = (struct load_command*) (mh + 1);
        for (uint32_t i=0; i < mh->ncmds && ((uint64_t)loadCmd) - ((uint64_t)mh) < PAGE_SIZE_64*4; i++) {
            if (loadCmd->cmd == LC_SEGMENT) {
                struct segment_command* segment = (struct segment_command*)loadCmd;
                if (segment->vmaddr == 0 && segment->vmsize != 0 && segment->initprot == 0 && segment->maxprot == 0 && strcmp("__PAGEZERO", segment->segname) == 0) {
                    _FREE(mh, M_TEMP);
                    return 0;
                }
            }
            loadCmd = (struct load_command *)((uint64_t)loadCmd + (uint64_t)loadCmd->cmdsize);
        }
        IOLog("NULLGuard: Binary without __PAGEZERO or with invalid __PAGEZERO killed.\n");
        _FREE(mh, M_TEMP);
        return 1;
    }
    _FREE(mh, M_TEMP);
    return 0;
}

int nullguard_execve(kauth_cred_t cred, kauth_cred_t new, struct proc* p, struct vnode* vp) {
    struct mach_header* mh = _MALLOC(PAGE_SIZE_64*4, M_TEMP, M_ZERO);
    if (!mh) {
        return 1;
    }
    get_mach_header(mh, vp, 0);
    if (mh->magic == FAT_MAGIC || mh->magic == FAT_CIGAM) {
        struct fat_header* fh = (struct fat_header*)mh;
        struct fat_arch* arch = (struct fat_arch*)(fh+1);
        for (int i = 0; i < fh->nfat_arch && i * sizeof(struct fat_arch) < PAGE_SIZE*4; i++) {
            struct mach_header* mha = _MALLOC(PAGE_SIZE_64*4, M_TEMP, M_ZERO);
            if (!mha) {
                _FREE(mh, M_TEMP);
                return 1;
            }
            get_mach_header(mha, vp, arch->offset);
            
            if (nullguard_checkmh(mha)) {
                _FREE(mh, M_TEMP);
                return 1;
            }
            arch ++;
        }
        _FREE(mh, M_TEMP);
    }
    return nullguard_checkmh(mh);
}

static struct mac_policy_ops ops = {
    .mpo_cred_label_update_execve = (void*)nullguard_execve,
};

static struct mac_policy_conf taskguard_macf = {
    .mpc_name = "nullguard",
    .mpc_fullname = "NULLGuard",
    .mpc_ops = &ops,
    .mpc_loadtime_flags = MPC_LOADTIME_FLAG_UNLOADOK,
};

static mac_policy_handle_t h=0;


kern_return_t NULLGuard_start(kmod_info_t * ki, void *d)
{
    mac_policy_register(&taskguard_macf, &h, d);
    return KERN_SUCCESS;
}

kern_return_t NULLGuard_stop(kmod_info_t *ki, void *d)
{
    mac_policy_unregister(h);
    return KERN_SUCCESS;
}
