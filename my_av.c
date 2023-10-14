// COPYRIGHT RUSU BOGDAN, 312CAa 2022-2023
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
	int size;
	char **dom;

} db_t; //database structure for the database input

void read_database(db_t *db, FILE *in_db)
{
	char domain[400]; // the string we use to read from the file
	while (fgets(domain, 400, in_db)) {
		domain[strlen(domain) - 1] = '\0';
		if (db->size == 0) {
			db->size++;
			db->dom = (char **)malloc(1 * sizeof(char *)); // alloc 1st element
			if (!db->dom) {
				printf("Could not allocate a database domain\n");
				fclose(in_db);
				return;
			}
			db->dom[0] = (char *)malloc((strlen(domain) + 1) * sizeof(char));
			if (!db->dom[0]) {
				printf("Could not allocate a database domain\n");
				fclose(in_db);
				free(db->dom);
				return;
			}
			strcpy(db->dom[0], domain); // copy the contents of the read string
		} else {
			char **tmp;
			db->size++;
			// there we have to realloc the matrix to the coresponding new size
			tmp = (char **)realloc(db->dom, db->size * sizeof(char *));
			if (!tmp) {
				printf("Could not allocate a database domain\n");
				fclose(in_db);
				for (int i = 0; i < db->size - 1; i++)
					free(db->dom[i]);
				free(db->dom);
				return;
			}
			db->dom = tmp; // only if we succeed in reallocating we go to the
			// new address
			db->dom[db->size - 1] = malloc((strlen(domain) + 1) * sizeof(char));
			if (!db->dom[db->size - 1]) {
				printf("Could not allocate a database domain\n");
				fclose(in_db);
				for (int i = 0; i < db->size - 1; i++)
					free(db->dom[i]);
				free(db->dom);
				return;
			}
			strcpy(db->dom[db->size - 1], domain); // copying the contents into
			// the element
		}
	}
}

int check_url_from_db(char *url, db_t db)
{
	// we check if the parameter url exists in the
	// database of known malicious urls
	for (int i = 0; i < db.size; i++)
		if (strstr(url, db.dom[i]))
			return 1;
	return 0;
}

void free_db(db_t *db)
{
	// function used to free the space allocated
	// for the database
	for (int i = 0; i < db->size; i++)
		free(db->dom[i]);
	free(db->dom);
}

int check_url_for_ext(char *url)
{
	// function to check if the url ends with one of the
	// malicious extensions listed below
	char ext[80][15] = {".exe", ".bin", ".pdf", ".doc", ".sh",
					   ".pl", ".jpg", ".cc", ".com", ".m", ".net",
					   ".dz", ".ga", ".cf", ".pw", ".css", ".dat",
					   ".ke", ".uk", ".pm", ".png", ".jpeg", ".32",
					   ".br", ".xls"};
	for (int i = 0; i < 25; i++) {
		if (strlen(url) >= strlen(ext[i])) {
			// we position ourselves at the exact point to make
			// the comparison
			char *p = url + strlen(url) - strlen(ext[i]);
			if (strcmp(p, ext[i]) == 0)
				return 1;
		}
	}
	return 0;
}

int min_3(int x, int y, int z)
{
	// function that returns the minimum value
	// out of 3 integers
	if (x <= y && x <= z)
		return x;
	if (y <= x && y <= z)
		return y;
	if (z <= x && z <= y)
		return z;
	return x;
}

int edit_dist(char *str1, char *str2, int n, int m)
{
	// function to calculate the levenshtein distance
	// between two strings
	// some bit of dyn-prog there
	// dp[i][j] = means the distance between the two
	// strings that contain the first i and j characters
	// from the strings, respectively
	// if a string is empty, the distance between it
	// and the other is equal to the current dimension of
	// the second one
	// if the current end characters of both strings are
	// equal, then we can go to the next characters to the left
	// because there is nothing to change between them
	// if they are not equal
	// then we have 3 options
	// we can either insert, remove or replace
	// the current characters
	// and we choose the best option out of the three
	int dp[50][50] = {0};
	for (int i = 0; i <= n; i++)
		for (int j = 0; j <= m; j++) {
			if (i == 0)
				dp[0][j] = j;
			else if (j == 0)
				dp[i][0] = i;
			else if (str1[i - 1] == str2[j - 1])
				dp[i][j] = dp[i - 1][j - 1];
			else
				dp[i][j] = 1 + min_3(dp[i - 1][j], dp[i][j - 1],
									 dp[i - 1][j - 1]);
		}
	return dp[n][m];
}

int check_sim(char *url)
{
	// using the levenshtein distance we determine if the
	// domain of the current url is an altered version of
	// the good, known urls listed below
	char *cp = strdup(url);
	char *domain = strtok(cp, ".");
	char good_urls[11][20] = {"whatsapp", "facebook", "paypal", "youtube",
							  "steamcommunity", "pay-pal", "instagram", "drive",
							  "steam", "snapchat", "google"};
	int fishy = 0;
	int same = 0;
	for (int i = 0; i < 11; i++) {
		int dist = edit_dist(domain, good_urls[i], strlen(domain),
							 strlen(good_urls[i]));
		// if the distance is small, but not 0,
		// then the current url is a malicious one
		if (dist > 0 && dist < 3)
			fishy = 1;
		// if the distance is 0, then the url domain is
		// a legitimate one
		if (!dist)
			same = 1;
	}
	free(cp);
	// we only return 1 (malicious) if it similar to one of the domains above
	// but not equal to any of them
	if (fishy && !same)
		return 1;
	return 0;
}

int check_dom_for_digits(char *url)
{
	char cp[1500];
	// string of characters that are not allowed in the domain
	char not_allowed[] = "!@#$%^&();:,?/\\=+<>_[]{}~";
	strcpy(cp, url); // we copy into cp so as not to alter
	// the contents of url by using strtok
	// we now extract the domain using strtok
	char *dom = strtok(cp, "/");
	if (!strcmp(dom, "http:") || !strcmp(dom, "https:"))
		dom = strtok(NULL, "/");
	int cnt = 0;
	// if any of the unallowed characters appear, then the url
	// is malicious
	for (int i = 0; i < (int)strlen(dom); i++)
		if (strchr(not_allowed, dom[i]))
			return 1;
	// now we count the digits and
	// if their numbers exceeds the given count
	// the url is malicious
	for (int i = 0; i < (int)strlen(dom); i++)
		if (dom[i] >= '0' && dom[i] <= '9')
			cnt++;
	if (3.0 * cnt >= 1.0 * strlen(dom))
		return 1;
	return 0;
}

int check_dom_length(char *url)
{
	// simple function to check the domain length
	// if it is too long, it can be a sign of
	// malicious activity
	char cp[1500];
	strcpy(cp, url);
	char *dom = strtok(cp, "/");
	if (strlen(dom) > 40)
		return 1;
	return 0;
}

// the next function checks the traffic, given at input
// for the second task of the problem
// it splits the given traffic into tokens, as the traffic
// is given into csv format
// and analyses the tokens at the respective positions
// as mentioned in the README
// for cnt == 17 we extract the flow_packets_payload_avg component
// for cnt == 12 we extract the ACK_flag
// for cnt == 11 we extract the SYN_flag
// for cnt == 10 we extract the FIN_flag
// for cnt == 14 we extract the backward_packets
// for cnt == 3 we extract the response_ip
// as said in the README
// if the conditions below are met
// then the traffic is either cryptomining (first operand of ||)
// or bruteforce (second operand of ||)

int check_traffic(char *traffic)
{
	char *cp = strdup(traffic);
	char *p = strtok(cp, ",");
	int atk = 0, cnt = 0;
	double avg = 0, intr = 0, rat = 0;
	int ack_flag = 0, response_ip_valid = 1;
	int bwd_packets = 0, fin_flag = 0, syn_flag = 0;
	while (p) {
		cnt++;
		if (cnt == 17) {
			int i = 0;
			while (i < (int)strlen(p) && p[i] >= '0' && p[i] <= '9') {
				intr = intr * 10 + p[i] - '0';
				i++;
			}
			i++;
			double p10 = 10.0;
			while (i < (int)strlen(p) && p[i] >= '0' && p[i] <= '9') {
				rat = rat + (p[i] - '0') / p10;
				i++;
				p10 *= 10.0;
			}
			avg = intr + rat;
		} else if (cnt == 12) {
			int i = 0;
			while (i < (int)strlen(p)) {
				ack_flag = ack_flag * 10 + p[i] - '0';
				i++;
			}
		} else if (cnt == 3) {
			if (strcmp(p, "255.255.255.255") == 0)
				response_ip_valid = 0;
			for (int i = 0; p[i]; i++)
				if (!((p[i] >= '0' && p[i] <= '9') || p[i] == '.'))
					response_ip_valid = 0;
		} else if (cnt == 14) {
			int i = 0;
			while (i < (int)strlen(p) && p[i] != '.') {
				bwd_packets = bwd_packets * 10 + p[i] - '0';
				i++;
			}
		} else if (cnt == 11) {
			int i = 0;
			while (i < (int)strlen(p)) {
				syn_flag = syn_flag * 10 + p[i] - '0';
				i++;
			}
		} else if (cnt == 10) {
			int i = 0;
			while (i < (int)strlen(p)) {
				fin_flag = fin_flag * 10 + p[i] - '0';
				i++;
			}
		}
		p = strtok(NULL, ",");
	}
	//crypto + bruteforce
	if ((!fin_flag && !syn_flag && !ack_flag && response_ip_valid &&
	     avg <= 225.0 && bwd_packets <= 10) || ack_flag >= 80)
		atk = 1;
	free(cp);
	return atk;
}

int check_undefined_param(char *url)
{
	// function that checks if the given url has an undefined
	// parameter, or ends with an unfinished query
	if (url[strlen(url) - 1] == '=' || url[strlen(url) - 1] == '?' ||
	    url[strlen(url) - 1] == '&')
		return 1;
	return 0;
}

int have_lang_in_path(char *url)
{
	// function that checks if there is 'html' or 'php'
	// in path as they usually come with their extension
	// in legit websites
	char *cp = strdup(url);
	char *p = strtok(cp, "/");
	while (p) {
		if (strcmp(p, "html") == 0 || strcmp(p, "php") == 0) {
			free(cp);
			return 1;
		}
		p = strtok(NULL, "/");
	}
	free(cp);
	return 0;
}

int check_download(char *url)
{
	// function that checks if the word download is present in the url
	// as this can lead to unwanted software on the user's computer
	char *p = strstr(url, "download");
	if (p) {
		int cnt = 0;
		for (int i = p - url; url[i]; i++)
			if (url[i] == '/')
				cnt++;
		if (cnt == 0)
			return 1;
		return 0;
	}
	return 0;
}

int domains_in_path(char *url)
{
	// function that checks if there are domains in the path of an url
	// this can be an attempt of phishing
	char *cp = strdup(url), *p;
	p = strtok(cp, "/");
	p = strtok(NULL, "/");
	char phishing_urls[20][20] = {"paypal.com", "Paypal.com", "twitter.com",
								  "facebook.com", "youtube.com",
								  "instagram.com", "whatsapp.com",
								  "snapchat.com"};
	while (p) {
		for (int i = 0; i < 8; i++)
			if (strstr(p, phishing_urls[i])) {
				free(cp);
				return 1;
			}
		p = strtok(NULL, "/");
	}
	free(cp);
	return 0;
}

int main(void)
{
	char input_file[] = "./data/urls/urls.in";
	char database[] = "./data/urls/domains_database";
	char output_file_t1[] = "urls-predictions.out";
	db_t db;
	db.size = 0;
	FILE *in_db = fopen(database, "rt");
	if (!in_db) {
		printf("Could not open database file %s\n", database);
		return 1;
	}
	read_database(&db, in_db);
	fclose(in_db);
	char *url = (char *)malloc(1500 * sizeof(char));
	FILE *in = fopen(input_file, "rt");
	if (!in) {
		printf("Could not open input file %s\n", input_file);
		free(url);
		return 1;
	}
	FILE *out = fopen(output_file_t1, "wt");
	while (fgets(url, 1500, in)) {
		int ok = 0;
		url[strlen(url) - 1] = '\0';
		ok = check_url_from_db(url, db);
		if (!ok)
			ok = check_url_for_ext(url);
		if (!ok)
			ok = check_dom_length(url);
		if (!ok)
			ok = check_sim(url);
		if (!ok)
			ok = check_undefined_param(url);
		if (!ok)
			ok = have_lang_in_path(url);
		if (!ok)
			ok = check_download(url);
		if (!ok)
			ok = domains_in_path(url);
		if (!ok)
			ok = check_dom_for_digits(url);
		fprintf(out, "%d\n", ok);
	}
	free_db(&db);
	free(url);
	fclose(in);
	fclose(out);
	char input_traf[] = "./data/traffic/traffic.in";
	char output_file_t2[] = "traffic-predictions.out";
	in = fopen(input_traf, "rt");
	if (!in) {
		printf("Could not open file %s\n", input_traf);
		return 1;
	}
	out = fopen(output_file_t2, "wt");
	if (!out) {
		printf("Could not open file %s\n", output_file_t2);
		fclose(in);
		return 1;
	}
	char *traffic = (char *)malloc(1000 * sizeof(char));
	fgets(traffic, 1000, in);
	while (fgets(traffic, 1000, in)) {
		int atk = 0;
		atk = check_traffic(traffic);
		fprintf(out, "%d\n", atk);
	}
	fclose(in);
	fclose(out);
	free(traffic);
	return 0;
}
