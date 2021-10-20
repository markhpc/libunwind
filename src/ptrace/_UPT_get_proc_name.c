/* libunwind - a platform-independent unwind library
   Copyright (C) 2003 Hewlett-Packard Co
   Copyright (C) 2007 David Mosberger-Tang
        Contributed by David Mosberger-Tang <dmosberger@gmail.com>

This file is part of libunwind.

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.  */

#include "_UPT_internal.h"

static int
get_unwind_info (struct elf_dyn_info *edi, pid_t pid,
                 unsigned long *segbase, unsigned long *mapoff,
                 unw_addr_space_t as, unw_word_t ip)
{
  char path[PATH_MAX];

#if UNW_TARGET_IA64 && defined(__linux)
  if (!edi->ktab.start_ip && _Uia64_get_kernel_table (&edi->ktab) < 0)
    return -UNW_ENOINFO;

  if (edi->ktab.format != -1 && ip >= edi->ktab.start_ip && ip < edi->ktab.end_ip)
    return 0;
#endif

  if ((edi->di_cache.format != -1
       && ip >= edi->di_cache.start_ip && ip < edi->di_cache.end_ip)
#if UNW_TARGET_ARM
      || (edi->di_debug.format != -1
       && ip >= edi->di_arm.start_ip && ip < edi->di_arm.end_ip)
#endif
      || (edi->di_debug.format != -1
       && ip >= edi->di_debug.start_ip && ip < edi->di_debug.end_ip))
    return 0;

  invalidate_edi(edi);

  if (tdep_get_elf_image (&edi->ei, pid, ip, segbase, mapoff, path,
                          sizeof(path)) < 0)
    return -UNW_ENOINFO;

  /* Here, SEGBASE is the starting-address of the (mmap'ped) segment
     which covers the IP we're looking for.  */
  if (tdep_find_unwind_table (edi, as, path, *segbase, *mapoff, ip) < 0)
    return -UNW_ENOINFO;

  /* This can happen in corner cases where dynamically generated
     code falls into the same page that contains the data-segment
     and the page-offset of the code is within the first page of
     the executable.  */
  if (edi->di_cache.format != -1
      && (ip < edi->di_cache.start_ip || ip >= edi->di_cache.end_ip))
     edi->di_cache.format = -1;

  if (edi->di_debug.format != -1
      && (ip < edi->di_debug.start_ip || ip >= edi->di_debug.end_ip))
     edi->di_debug.format = -1;

  if (edi->di_cache.format == -1
#if UNW_TARGET_ARM
      && edi->di_arm.format == -1
#endif
      && edi->di_debug.format == -1)
    return -UNW_ENOINFO;

  return 0;
}

int
get_proc_name (unw_addr_space_t as, unw_word_t ip,
               char *buf, size_t buf_len, unw_word_t *offp, void *arg)
{
  struct UPT_info *ui = arg;
  struct elf_dyn_info *edi = &ui->edi;
  unsigned long segbase, mapoff;
  int ret;
  char file[PATH_MAX];

  ret = get_unwind_info (edi, ui->pid, &segbase, &mapoff, as, ip);
  if (ret < 0)
    return ret;

  ret = _Uelf64_load_debuglink (file, &edi->ei, 1);
  if (ret < 0)
    return ret;

  ret = _Uelf64_get_proc_name_in_image (as, &edi->ei, segbase, mapoff, ip, buf, buf_len, offp);

  return ret;
}

int
_UPT_get_proc_name (unw_addr_space_t as, unw_word_t ip,
                    char *buf, size_t buf_len, unw_word_t *offp, void *arg)
{
  struct UPT_info *ui = arg;

#if UNW_ELF_CLASS == UNW_ELFCLASS64
//  return _Uelf64_get_proc_name (as, ui->pid, ip, buf, buf_len, offp);
  return get_proc_name (as, ip, buf, buf_len, offp, arg);
#elif UNW_ELF_CLASS == UNW_ELFCLASS32
  return _Uelf32_get_proc_name (as, ui->pid, ip, buf, buf_len, offp);
#else
  return -UNW_ENOINFO;
#endif
}
