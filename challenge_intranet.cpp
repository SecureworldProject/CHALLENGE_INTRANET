
/////  FILE INCLUDES  /////
#include "pch.h"
#include "context_challenge.h"
#include "json.h"
#include <stdio.h>
#include <stdlib.h>





/////  DEFINITIONS  /////
#define CHPRINT(...) do { printf("CHALLENGE_INTRANET --> "); printf(__VA_ARGS__); } while (0)
#define ERRCHPRINT(...) do { fprintf(stderr, "ERROR in CHALLENGE_INTRANET --> "); fprintf(stderr, __VA_ARGS__); } while (0)





/////  GLOBAL VARIABLES  /////
char* target_SSID = NULL;
char** urls = NULL;




/////  FUNCTION DEFINITIONS  /////
void getChallengeParameters();
char* getCurrentWifiSSID();
BOOL ping(char* url);
void setBitTrue(byte * buf, int pos);





/////  FUNCTION IMPLEMENTATIONS  /////
int init(struct ChallengeEquivalenceGroup* group_param, struct Challenge* challenge_param) {
	int result = 0;

	// It is mandatory to fill these global variables
	group = group_param;
	challenge = challenge_param;
	if (group == NULL || challenge == NULL) {
		ERRCHPRINT("ChGroup and/or Challenge are NULL \n");
		return -1;
	}
	CHPRINT("Initializing (%ws) \n", challenge->file_name);

	// Process challenge parameters
	getChallengeParameters();

	// It is optional to execute the challenge here
	result = executeChallenge();

	// It is optional to launch a thread to refresh the key here, but it is recommended
	if (result == 0) {
		launchPeriodicExecution();
	}

	return result;
}

int executeChallenge() {
	DWORD result = ERROR_SUCCESS;

	char* ssid = NULL;
	size_t ssid_len = 0;
	size_t url_num = 0;
	size_t urls_results_size = 0;
	byte* urls_results_buf = NULL;

	byte* key_data = NULL;
	size_t size_of_key = 0;
	time_t new_validity_time = 0;
	CHPRINT("Execute (%ws)\n", challenge->file_name);
	if (group == NULL || challenge == NULL)	return -1;

	// Get the SSID
	ssid = getCurrentWifiSSID();
	if (ssid==NULL){
		result = -1;
		goto CLEANUP;
	}
	ssid_len = strlen(ssid);
	printf("******* ssid = '%s'\n", ssid);
	printf("******* ssid_len = %llu\n", ssid_len);


	// Check resposnse to the urls
	url_num = _msize(urls) / sizeof(char*);
	urls_results_size = (int)(url_num / 8) + ((url_num % 8 == 0) ? 0 : 1);
	printf("******* urls_results_size = %llu\n", urls_results_size);
	urls_results_buf = (byte*)calloc(urls_results_size, sizeof(byte));      // Important calloc so it is initialized to 0s
	if (urls_results_buf == NULL) {
		result = -1;
		goto CLEANUP;
	}
	for (size_t i = 0; i < url_num; i++) {
		if (ping(urls[i])) {
			setBitTrue(urls_results_buf, i);
			printf("******* set bit true in pos = %llu\n", i);
		}
	}
	printf("******* urls_results_buf = 0x%02hhx    or   %d\n", urls_results_buf[0], urls_results_buf[0]);

	// Prepare the key before the critical section, so it is as smmall as possible
	size_of_key = ssid_len + urls_results_size;
	key_data = (byte*)malloc(ssid_len + urls_results_size);
	if (key_data == NULL) {
		result = -1;
		goto CLEANUP;
	}
	memcpy_s(key_data, size_of_key, ssid, ssid_len);
	memcpy_s(&(key_data[ssid_len]), size_of_key - ssid_len, urls_results_buf, urls_results_size);
	new_validity_time = time(NULL) + validity_time;


	//CHPRINT(" --- ENTERING CRITICAL SECTION --- \n");
	EnterCriticalSection(&(group->subkey->critical_section));
	if (group->subkey->data != NULL) {
		free(group->subkey->data);
	}
	group->subkey->data = key_data;
	group->subkey->size = size_of_key;
	group->subkey->expires = new_validity_time;
	LeaveCriticalSection(&(group->subkey->critical_section));
	//CHPRINT(" --- LEAVING CRITICAL SECTION --- \n");

	CLEANUP:
	if (ssid != NULL) {
		free(ssid);
	}
	if (urls_results_buf != NULL) {
		free(urls_results_buf);
	}

	return 0;   // Always 0 means OK.
}

void getChallengeParameters() {
	int str_len = 0;
	int num_urls = 0;
	json_value* props = NULL;
	json_object_entry prop_i = { 0 };
	json_value* jv_urls = NULL;
	json_value* url_j = { 0 };
	DWORD err = ERROR_SUCCESS;

	CHPRINT("Getting challenge parameters\n");

	props = challenge->properties;
	for (int i = 0; i < props->u.object.length; i++) {
		prop_i = props->u.object.values[i];
		if (strcmp(prop_i.name, "validity_time") == 0) {
			validity_time = (int)(prop_i.value->u.integer);
			CHPRINT(" * Property: validity_time\n");
			CHPRINT("     - Value: %d\n", validity_time);
		} else if (strcmp(prop_i.name, "refresh_time") == 0) {
			refresh_time = (int)(prop_i.value->u.integer);
			CHPRINT(" * Property: refresh_time\n");
			CHPRINT("     - Value: %d\n", refresh_time);
		} else {
			// Challenge specific parameters (none)
			if (strcmp(prop_i.name, "SSID") == 0) {
				str_len = prop_i.value->u.string.length;
				target_SSID = (char*) malloc(sizeof(char) * (str_len + 1));
				strcpy_s(target_SSID, str_len+1, prop_i.value->u.string.ptr);
				CHPRINT(" * Property: SSID\n");
				CHPRINT("     - Value: %s\n", target_SSID);
			} else if (strcmp(prop_i.name, "urls") == 0) {
				// Be careful when adding servers outside the intranet. Servers of those URLs could be down for any reason which would lead to a change in the challenge subkey
				// Could be useful if the URLs are of essential services inside the enterprise intranet
				jv_urls = prop_i.value;
				num_urls = jv_urls->u.array.length;
				CHPRINT(" * Property: urls (a total of %d)\n", num_urls);
				urls = (char**)malloc(sizeof(char*) * num_urls);
				if (urls == NULL) {
					ERRCHPRINT("No memory for assigning space\n");
					return;
				}

				for (size_t j = 0; j < num_urls; j++) {
					url_j = jv_urls->u.array.values[j];
					str_len = url_j->u.string.length;
					urls[j] = (char*)malloc(sizeof(char) * (str_len + 1));
					strcpy_s(urls[j], str_len + 1, url_j->u.string.ptr);
					CHPRINT("     - Value: %s\n", urls[j]);
				}
			} else {
				CHPRINT("Unknown property\n");
			}
		}
	}
}

char* getCurrentWifiSSID() {
	FILE* fp = NULL;
	char* tmp_ptr = NULL;
	char cmd_result_line[1025];
	char* result = NULL;
	int res_size = 0;

	// Open a process with the output piped to a read stream
	fp = _popen("netsh wlan show int", "r");
	if (fp == NULL) {
		ERRCHPRINT("Failed to get current wifi SSID\n");
		exit(1);
	}

	// Read oputput line by line
	while (fgets(cmd_result_line, sizeof(cmd_result_line), fp) != NULL) {
		// In theory the SSID line is like this: "    SSID                   : NAME_OF_THE_NETWORK"
		if (strstr(cmd_result_line, " SSID ") != NULL) {
			tmp_ptr = strstr(cmd_result_line, ":");
			if (tmp_ptr != NULL) {
				tmp_ptr += 2;                                           // +2 to start after the colon and space
				CHPRINT("SSID: %s", tmp_ptr);
				//CHPRINT("%s", cmd_result_line+29);
				res_size = strlen(tmp_ptr) - 1 + 1;                     // -1 because it ends in '\n' adn +1 for the null char
				result = (char*)malloc(res_size * sizeof(char));
				if (result != NULL) {
					memcpy_s(result, res_size, tmp_ptr, res_size - 1);  // -1 not to copy the ending '\n'
					result[res_size - 1] = '\0';
				}
			}
		}
	}

	// Close the piped process
	_pclose(fp);

	return result;
}

BOOL ping(char* url) {
	BOOL result = FALSE;
	BOOL retry = TRUE;

	// Send ping to the url and check if destination was reachable
	FILE* fp = NULL;
	char cmd_input_base[] = "ping -n 3 -w 1000 ";
	char* cmd_input = NULL;
	char* tmp_ptr = NULL;
	char cmd_result_line[1025];

	size_t url_len = 0;
	size_t cmd_input_base_len = 0;
	size_t cmd_input_size = 0;

	// Create the command
	url_len = strlen(url);
	cmd_input_base_len = strlen(cmd_input_base);
	cmd_input_size = (cmd_input_base_len + url_len + 1) * sizeof(char);
	cmd_input = (char*)malloc(cmd_input_size);
	if (cmd_input == NULL) {
		ERRCHPRINT("Failed to launch a ping to %s (not enough memory)\n", url);
		return FALSE;
	}
	strcpy_s(cmd_input, cmd_input_size, cmd_input_base);
	strcpy_s(cmd_input + cmd_input_base_len, cmd_input_size - cmd_input_base_len, url);

	while (retry) {
		retry = FALSE;

		// Open a process with the output piped to a read stream
		fp = _popen(cmd_input, "r");
		if (fp == NULL) {
			ERRCHPRINT("Failed to launch a ping to %s\n", url);
			exit(1);
		}

		// Read oputput line by line
		CHPRINT("Pinging %s\n", url);
		while (fgets(cmd_result_line, sizeof(cmd_result_line), fp) != NULL) {
			// In theory the statistics line is like this: "    (33% lost),"  and it is the only one with parenthesis and percentage characters
			tmp_ptr = strstr(cmd_result_line, "(");
			if (tmp_ptr != NULL) {
				tmp_ptr = strstr(tmp_ptr, "%");
				if (tmp_ptr != NULL) {
					if (tmp_ptr[-1] == '0' && tmp_ptr[-2] == '(') {                                                     // Looking for:   "(0%"
						//CHPRINT("All responses received\n");
						result = TRUE;
					} else if (tmp_ptr[-1] == '0' && tmp_ptr[-2] == '0' && tmp_ptr[-3] == '1' && tmp_ptr[-4] == '(') {  // Looking for: "(100%"
						//CHPRINT("No responses received\n");
						result = FALSE;
					} else {
						CHPRINT("Inconsistent responses, retrying...\n");
						retry = TRUE;
						//result = TRUE;	If it was accessible at least one time, it is "accessible" at least in general
					}
				}
			}
		}

		// Close the piped process
		_pclose(fp);
	}


	CHPRINT("Result: %s\n", (result? "OK":"UNREACHABLE"));
	return result;
}

void setBitTrue(byte* buf, int pos){
	int complete_bytes = pos / 8;
	int extra_bits = pos % 8;
	byte mask = 0x01 << extra_bits;
	buf[complete_bytes] |= mask;
	return;
}
