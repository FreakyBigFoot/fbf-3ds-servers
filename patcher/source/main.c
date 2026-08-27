// FFE Connect — one-tap patcher for playing Final Fantasy Explorers on the
// ffe.freakybigfoot.com self-hosted server.
//
// CONNECT: reads this console's NEX PID + password from the friends module,
//          registers them with the server (raw-socket HTTP POST), and installs
//          the NASC redirect to /luma/sysmodules/0004013000003202.ips.
// UNDO:    restores Nimbus's original pretendo.cc patch (back to normal Pretendo).
//
// Only FF Explorers is redirected to our server; every other Pretendo game is
// proxied straight through, so they keep working.

#include <3ds.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <malloc.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "friends_patch.h"   // friends_patch_ips  (ffe.freakybigfoot.com)
#include "nimbus_orig.h"     // nimbus_orig_ips    (pretendo.cc)

#define SERVER_HOST "ffe.freakybigfoot.com"
#define SERVER_IP   "209.141.53.207"          // DNS fallback
#define PATCH_PATH  "/luma/sysmodules/0004013000003202.ips"

#define C_RESET  "\x1b[0m"
#define C_CYAN   "\x1b[36m"
#define C_GREEN  "\x1b[32m"
#define C_YELLOW "\x1b[33m"
#define C_RED    "\x1b[31m"

static PrintConsole topScreen, botScreen;

// ---- helpers ---------------------------------------------------------------

static size_t url_encode(char *dst, size_t dstsz, const char *src) {
	static const char hex[] = "0123456789ABCDEF";
	size_t o = 0;
	for (const unsigned char *p = (const unsigned char *)src; *p; p++) {
		unsigned char c = *p;
		int unreserved = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
		                 (c >= '0' && c <= '9') || c == '-' || c == '_' ||
		                 c == '.' || c == '~';
		if (unreserved) { if (o + 1 >= dstsz) break; dst[o++] = (char)c; }
		else { if (o + 3 >= dstsz) break; dst[o++] = '%'; dst[o++] = hex[c >> 4]; dst[o++] = hex[c & 0xF]; }
	}
	dst[o] = 0;
	return o;
}

// POST pid+password over a raw BSD socket. Returns HTTP status, 0 on error.
static u32 register_account(u32 pid, const char *password) {
	char encpw[256], body[512], req[1024], resp[512];
	url_encode(encpw, sizeof(encpw), password);
	int blen = snprintf(body, sizeof(body), "pid=%lu&password=%s", (unsigned long)pid, encpw);
	if (blen <= 0) return 0;

	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(80);
	struct hostent *he = gethostbyname(SERVER_HOST);
	if (he && he->h_addr_list && he->h_addr_list[0])
		memcpy(&addr.sin_addr, he->h_addr_list[0], he->h_length);
	else
		addr.sin_addr.s_addr = inet_addr(SERVER_IP);

	int fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) return 0;
	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) { closesocket(fd); return 0; }

	int rlen = snprintf(req, sizeof(req),
		"POST /register HTTP/1.0\r\nHost: %s\r\n"
		"Content-Type: application/x-www-form-urlencoded\r\n"
		"Content-Length: %d\r\nConnection: close\r\n\r\n%s",
		SERVER_HOST, blen, body);

	int sent = 0;
	while (sent < rlen) {
		int w = send(fd, req + sent, rlen - sent, 0);
		if (w <= 0) { closesocket(fd); return 0; }
		sent += w;
	}
	int n = recv(fd, resp, sizeof(resp) - 1, 0);
	closesocket(fd);
	if (n <= 0) return 0;
	resp[n] = 0;
	int status = 0;
	sscanf(resp, "HTTP/1.%*d %d", &status);
	return (u32)status;
}

static bool write_patch(const unsigned char *data, unsigned int len) {
	mkdir("/luma", 0777);
	mkdir("/luma/sysmodules", 0777);
	FILE *f = fopen(PATCH_PATH, "wb");
	if (!f) return false;
	size_t n = fwrite(data, 1, len, f);
	fclose(f);
	return n == len;
}

// ---- screens ---------------------------------------------------------------

static void draw_explanation(void) {
	consoleSelect(&topScreen);
	printf("\x1b[2J");
	printf(C_CYAN "  FFE Connect" C_RESET "  -  Final Fantasy Explorers online\n");
	printf("  ------------------------------------------\n\n");
	printf("  This lets you play FF Explorers online\n");
	printf("  on the community server.\n\n");
	printf("  When you CONNECT it:\n");
	printf("   - reads your (anonymous) NEX login\n");
	printf("   - registers it with the server\n");
	printf("   - points FF Explorers at the server\n\n");
	printf("  " C_GREEN "Every other Pretendo game keeps working" C_RESET "\n");
	printf("  - they're passed straight through.\n\n");
	printf("  Fully reversible: " C_YELLOW "UNDO" C_RESET " restores normal\n");
	printf("  Pretendo any time. Nothing is permanent.\n\n");
	printf("  " C_YELLOW "Change your Pretendo password later?" C_RESET "\n");
	printf("  Just run CONNECT again to update it.\n");
}

static void draw_menu(void) {
	consoleSelect(&botScreen);
	printf("\x1b[2J\n");
	printf("        Choose an option:\n\n");
	printf("    " C_GREEN "[ A ]" C_RESET "  Connect to FFE server\n\n");
	printf("    " C_YELLOW "[ Y ]" C_RESET "  Undo  (restore Pretendo)\n\n");
	printf("    " C_RED "[ B ]" C_RESET "  Exit\n\n");
	printf("  ------------------------------------------\n");
}

// Runs the connect flow; prints progress to the bottom screen. Returns success.
static bool do_connect(void) {
	consoleSelect(&botScreen);
	printf("\x1b[2J\n  Connecting...\n\n");

	printf("  Reading your NEX account... ");
	if (R_FAILED(frdInit(true))) { printf(C_RED "FAIL\n" C_RESET "  (Pretendo/Nimbus set up?)\n"); return false; }
	FriendKey key; memset(&key, 0, sizeof(key));
	Result r = FRD_GetMyFriendKey(&key);
	char password[256]; memset(password, 0, sizeof(password));
	if (R_SUCCEEDED(r)) r = FRD_GetMyPassword(password, sizeof(password));
	frdExit();
	if (R_FAILED(r) || key.principalId == 0 || password[0] == 0) {
		printf(C_RED "FAIL\n" C_RESET "  Connect to Pretendo online once first.\n");
		return false;
	}
	printf(C_GREEN "ok" C_RESET "  (PID %lu)\n", (unsigned long)key.principalId);

	printf("  Registering with server...  ");
	u32 status = register_account(key.principalId, password);
	memset(password, 0, sizeof(password));
	if (status != 200) { printf(C_RED "FAIL (%lu)\n" C_RESET "  Check your internet.\n", (unsigned long)status); return false; }
	printf(C_GREEN "ok" C_RESET "\n");

	printf("  Installing FFE patch...     ");
	if (!write_patch(friends_patch_ips, friends_patch_ips_len)) { printf(C_RED "FAIL\n" C_RESET "  SD writable?\n"); return false; }
	printf(C_GREEN "ok" C_RESET "\n\n");

	printf("  " C_GREEN "*** Connected! ***" C_RESET "\n\n");
	printf("  After the reboot: launch FF Explorers\n");
	printf("  and go online. Other games still work.\n");
	return true;
}

static bool do_undo(void) {
	consoleSelect(&botScreen);
	printf("\x1b[2J\n  Undoing...\n\n");
	printf("  Restoring normal Pretendo... ");
	if (!write_patch(nimbus_orig_ips, nimbus_orig_ips_len)) { printf(C_RED "FAIL\n" C_RESET "  SD writable?\n"); return false; }
	printf(C_GREEN "ok" C_RESET "\n\n");
	printf("  " C_YELLOW "Restored." C_RESET "  Reboot to finish.\n");
	printf("  Your account stays registered (harmless)\n");
	printf("  in case you reconnect later.\n");
	return true;
}

// reboot_now performs a full system reboot (ptm:sysm is granted in the RSF).
static void reboot_now(void) {
	consoleSelect(&botScreen);
	printf("\n  Rebooting...\n");
	gspWaitForVBlank();
	ptmSysmInit();
	PTMSYSM_RebootAsync(0);
	ptmSysmExit();
	while (aptMainLoop()) gspWaitForVBlank(); // hang until it reboots
}

// After a successful action, offer a one-tap reboot to apply it.
static void offer_reboot(void) {
	consoleSelect(&botScreen);
	printf("\n  " C_GREEN "Press A to REBOOT now" C_RESET " and apply it.\n");
	printf("  Press B to go back to the menu.\n");
	while (aptMainLoop()) {
		hidScanInput();
		u32 k = hidKeysDown();
		if (k & KEY_A) { reboot_now(); return; }
		if (k & KEY_B) { draw_menu(); return; }
		gspWaitForVBlank();
	}
}

// ---- main ------------------------------------------------------------------

int main(int argc, char **argv) {
	gfxInitDefault();
	consoleInit(GFX_TOP, &topScreen);
	consoleInit(GFX_BOTTOM, &botScreen);

	// bring up the network stack once (needed for the raw-socket POST).
	acInit();
	u32 *soc_buffer = (u32 *) memalign(0x1000, 0x100000);
	if (soc_buffer) socInit(soc_buffer, 0x100000);

	draw_explanation();
	draw_menu();

	while (aptMainLoop()) {
		hidScanInput();
		u32 kDown = hidKeysDown();
		if (kDown & KEY_A) {
			if (do_connect()) offer_reboot();
			else printf("\n  Press B to exit, or A/Y again.\n");
		} else if (kDown & KEY_Y) {
			if (do_undo()) offer_reboot();
			else printf("\n  Press B to exit, or A/Y again.\n");
		} else if (kDown & KEY_B) {
			break;
		}
		gspWaitForVBlank();
	}

	if (soc_buffer) socExit();
	acExit();
	gfxExit();
	return 0;
}
