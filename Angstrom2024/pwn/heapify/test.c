#include <stdio.h>
#include <stdlib.h>

#define INTERNAL_SIZE_T size_t
#define offsetof(type,ident) ((size_t)&(((type*)0)->ident))

struct malloc_chunk {

  INTERNAL_SIZE_T      mchunk_prev_size;  /* Size of previous chunk (if free).  */
  INTERNAL_SIZE_T      mchunk_size;       /* Size in bytes, including overhead. */

  struct malloc_chunk* fd;         /* double links -- used only if free. */
  struct malloc_chunk* bk;

  /* Only used for large blocks: pointer to next larger size.  */
  struct malloc_chunk* fd_nextsize; /* double links -- used only if free. */
  struct malloc_chunk* bk_nextsize;
};

int
main ( void ){
	printf("%x\n", offsetof(struct malloc_chunk, fd_nextsize));
	printf("%ld\n", sizeof( size_t ));
	printf("%ld\n", __alignof__ ( long double ));
	return 0;
}
