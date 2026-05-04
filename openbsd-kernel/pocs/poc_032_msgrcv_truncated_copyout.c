/*
 * Finding 032: sys_msgrcv reports a truncated length but copies all mbufs.
 *
 * Patched result:
 *   msgrcv() returns RECV_LEN and the post-msgsz canary remains unchanged.
 *
 * Vulnerable result:
 *   bytes after sizeof(long) + RECV_LEN are overwritten with queued message
 *   data even though the receive msgsz was only RECV_LEN.
 */

#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>

#include <err.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SEND_LEN	512
#define RECV_LEN	16
#define TRAILER_LEN	(SEND_LEN - RECV_LEN)
#define MSG_TYPE	1
#define CANARY		0xa5

struct send_msg {
	long mtype;
	unsigned char mtext[SEND_LEN];
};

static void
cleanup_queue(int qid)
{
	if (qid != -1)
		(void)msgctl(qid, IPC_RMID, NULL);
}

int
main(void)
{
	struct send_msg msg;
	unsigned char *recvbuf, *trailer;
	size_t alloc_len;
	ssize_t n;
	int qid = -1;
	size_t i, changed = 0;

	alloc_len = sizeof(long) + SEND_LEN + 64;
	recvbuf = calloc(1, alloc_len);
	if (recvbuf == NULL)
		err(1, "calloc");

	qid = msgget(IPC_PRIVATE, IPC_CREAT | 0600);
	if (qid == -1)
		err(1, "msgget");

	msg.mtype = MSG_TYPE;
	for (i = 0; i < sizeof(msg.mtext); i++)
		msg.mtext[i] = (unsigned char)(0x40 + (i & 0x3f));

	if (msgsnd(qid, &msg, sizeof(msg.mtext), 0) == -1) {
		cleanup_queue(qid);
		err(1, "msgsnd");
	}

	memset(recvbuf, 0, alloc_len);
	trailer = recvbuf + sizeof(long) + RECV_LEN;
	memset(trailer, CANARY, TRAILER_LEN);

	errno = 0;
	n = msgrcv(qid, recvbuf, RECV_LEN, MSG_TYPE, 0);
	if (n == -1) {
		int saved = errno;

		cleanup_queue(qid);
		errno = saved;
		err(1, "msgrcv");
	}

	cleanup_queue(qid);

	for (i = 0; i < TRAILER_LEN; i++) {
		if (trailer[i] != CANARY)
			changed++;
	}

	printf("msgrcv returned %zd bytes for requested msgsz=%d\n", n,
	    RECV_LEN);

	if (changed != 0) {
		printf("VULNERABLE: %zu canary bytes after msgsz were overwritten\n",
		    changed);
		printf("first overwritten byte: offset +%zu value 0x%02x\n",
		    (size_t)RECV_LEN, trailer[0]);
		free(recvbuf);
		return 2;
	}

	printf("PATCHED: canary after requested msgsz is intact\n");
	free(recvbuf);
	return 0;
}
