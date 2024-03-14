#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <stdint.h>
#include <getopt.h>
#include <ctype.h>
#include <string.h>
#include <string.h>
#include <signal.h>
#include <sys/time.h>
#include <pthread.h>

/*
 * User command line interface
 */
const char *g_version = "1.0.0";

#define CMD_NUM_MAX (16)
typedef int(*cncmd_handle)(char *args);

struct cnopt_args {
	int  opt;
	char *args;
};

struct cncmd_hub {
	int cmd_cnt;
	struct cnopt_args opt_args[CMD_NUM_MAX];
};

struct cnlut_cmd {
	const char *cmd_usage;
	cncmd_handle cmd_handle;
	int opt;
};

enum error_code {
	CMD_LINE_FAILED = 0x0001,
	MALLOC_FAILED = 0x0002,
};

static int do_user_cmd(int argc, char **argv);
static int callback_cmd_handle(int opt, char *args);
static int clear_cmd_hub(struct cncmd_hub *cmd_hub);
static int prepare_cmd(int argc, char **argv, struct cncmd_hub *cmd_hub);
static int serach_lut_cmd(int opt);
__attribute__((unused))
static void getopt_reset(void)
{
    	optarg = NULL;
	optind = 1;
	opterr = 1;
	optopt = '?';
}

//Handles of command line parameters and gloal varibale
static char g_error_action[32] = "exitall";  //exitall (DFL) stopself
static char g_plugincfg_path[256] = "complex_config/default.conf";
static int help_handle(char *args);
static int version_handle(char *args);
static int timecnt_handle(char *args);
static int list_handle(char *args);
static int filter_handle(char *args);
static int compare_handle(char *args);
static int erraction_handle(char *args);
static int plugincfg_handle(char *args);

static const char *opt_string = "h::vt:lf:c:e:p:";

static struct option long_options[] = {
    {"help", optional_argument, NULL, 'h'},
    {"version", no_argument, NULL, 'v'},
    {"timecnt", required_argument, NULL, 't'}, //time conut (minutes Higher than loop)
    {"list", no_argument, NULL, 'l'}, //list all these test cases support
    {"filter", required_argument, NULL, 'l'}, //filer which case to run
    {"erraction", required_argument, NULL, 'e'}, //config erraction

    /*The next all cases which accept string parameter*/
    {"plugincfg", required_argument, NULL, 'p'},

    {NULL} //THE END MARK
};

static struct cnlut_cmd rit_lut_cmd[] = {
	{"-h|--help ................ Show help infornation.\n", help_handle, 'h'},
	{"-v|--version ............. Show version of test.\n", version_handle, 'v'},
	{"-t|--timecnt N ........... Set how long test running, default 5 minutes.\n", timecnt_handle, 't'},
	{"-l|--list ................ List all these cases it support.\n", list_handle, 'l'},
	{"-f|--filter \"a;b\" ........ Filter which cases to run and -l can get list. default test all.\n", filter_handle, 'f'},
	{"-e|--erraction mode ...... Config erraction who has exitall or stopself, default exitall.\n", erraction_handle, 'e'},
	{"   --plugincfg path ...... Set test plugin config file, default 'complex_config/default.conf'.\n", plugincfg_handle, 'p'},
};

/*
 * plugin interface
 */
#define NAME_LEN (32)
#define CMDSTR_LEN (256)
struct case_config_s {
	long idx; //IF <0 Means END
	char name[NAME_LEN];
	char cmdstr[CMDSTR_LEN];
	long selected; //maybe changed by filter handle
};

#define CASE_MAX_CNT  (32)
static struct case_config_s g_case_config_tbl[CASE_MAX_CNT] = {
	{-1}
};

#define CASE_SEL_CHECK(id) do { \
	if (!g_case_config_tbl[id].selected) { \
		return NULL; \
	} \
} while (0)

#define PRESS_ANY_CONTINUE() do { \
	printf("\n<press any continue>\n\n"); \
	getchar(); \
} while (0)

/*
 * Thread controls
 */
#define thread_call_check_exit(index, name, ret) do { \
	if (ret) { \
		if (strstr(g_error_action, "exitall")) { \
			printf("\ncase-%d '%s' ret=%d FAILED exit all at once\n", index, name, ret); \
			exit(ret); \
		} else { \
			printf("\ncase-%d '%s' ret=%d FAILED stop itself only\n", index, name, ret); \
		} \
	} \
} while (0)

#define CTL_MAX_CNT  (CASE_MAX_CNT + 2)
#define CTL_ITEM(name_init, param_init, entry_init, retval_parse_init, signum_init) \
	{.name = name_init, \
	 .param = param_init, \
	 .entry = entry_init, \
	 .id = (pthread_t)0x33cc55aa, \
	 .signum = signum_init, \
	 .retval = NULL, \
	 .retval_parse = retval_parse_init}
typedef void*(*thread_entry)(void *arg);
typedef unsigned long(*thread_retval_parse)(void *retval);

struct thread_control_s {
	const char *name;
	void *param;
	thread_entry entry;
	pthread_t id;
	int signum;

	void *retval;
	thread_retval_parse retval_parse;
};

static volatile int g_force_stop_watch;
static struct timeval g_start_time;
static struct timeval g_current_time;
static long g_loop_cnt = 1; //At least keep run ONE whole loop
static long g_time_cnt = 5;
static volatile unsigned int g_time_arrive;
static int is_test_arrive_end(volatile long *loop_done, long finish);
static void *loop_watch(void *arg);
static int thread_init(void);  //Init thread_control if need dynamic
static int thread_go(void); //Create and let go
static int thread_result_show(void); //Joni and show
static int thread_manual_clean(void);

#define STOP_WATCH() do { \
g_force_stop_watch = 1; \
} while (0)
#define START_WATCH() do { \
g_force_stop_watch = 0; \
} while (0)

__attribute__((unused))
static int get_cmdline(char *line, int *argc, char **argv);
__attribute__((unused))
static void put_cmdline(int *argc, char **argv);

__attribute__((unused))
static int init_case_config(void);
__attribute__((unused))
static int init_thread_control(void);

static void *common_case_entry(void *arg);
static unsigned long common_case_retval_parse(void *retval);

static struct thread_control_s thread_control[CTL_MAX_CNT] = {
	[0]CTL_ITEM("loop_watch", NULL, loop_watch, NULL, 0), //DO NOT CHANGE
	[CTL_MAX_CNT -1]CTL_ITEM(NULL, NULL, NULL, NULL, 0) //DO NOT CHANGE
};

int main(int argc, char *argv[])
{
	int ret = 0;

	init_case_config();

	do_user_cmd(argc, argv);

  	thread_init();

	printf("Complex Test Begin >>>\n\n");
  	ret = thread_go();
	if (ret) {
		goto label_exit;
	}

	ret = thread_result_show();

label_exit:
	printf("\nComplext Test End and Ret=%d [%s] <<<\n\n", ret, ret ? "FAILED" : "PASSED");

	return ret;
}

__attribute__((unused))
static int get_cmdline(char *line, int *argc, char **argv)
{
	int len = 0;
	char *token = NULL;
	char *next_token = NULL;
	int cnt = 0;
	int ret = 0;
	char buff[512] = {0};
	int index = 0;

	len = strlen(line);
	if (len > 1 && !strstr(line, "#")) {
		token = strtok_r(line, " ", &next_token);
		while (token) {
			index += sprintf(buff + index, " %s", token);
			argv[cnt] = strdup(token);
			if (argv[cnt]) {
				cnt++;
			}
			token = strtok_r(NULL, " ", &next_token);
		}

		*argc = cnt;
		printf("Entry's InputParam [%d]:%s\n", cnt, buff);
	} else {
		ret = -1;
	}

	return ret;
}

__attribute__((unused))
static void put_cmdline(int *argc, char **argv)
{
	int cnt = *argc;

	while (--cnt >= 0) {
		free(argv[cnt]);
		argv[cnt] = NULL;
	}
	*argc = 0;

	return;
}


/***
 * Command line interface
 */
static int excute_cmd(struct cncmd_hub *cmd_hub)
{
	int total_cmd_cnt = 0;
	int i = 0;
	int j = 0;
	int k = 0;
	int m = 0;
	struct cncmd_hub previous_cmd_hub;  // Some cmd shall be done with high priority.
	struct cncmd_hub medium_cmd_hub;    // Some cms shall be done with medium priority.
	struct cncmd_hub latency_cmd_hub;   // Some cmd shall be done with low priority.

	previous_cmd_hub.cmd_cnt = 0;
	medium_cmd_hub.cmd_cnt = 0;
	latency_cmd_hub.cmd_cnt = 0;
	if (cmd_hub->cmd_cnt) {
		//printf("Have %d cmd to do...\n", cmd_hub->cmd_cnt);

		for (i = 0; i < cmd_hub->cmd_cnt; i++) {
			if (cmd_hub->opt_args[i].opt == 'h' ||
			    cmd_hub->opt_args[i].opt == 'v' ||
			    cmd_hub->opt_args[i].opt == 'p') {
				previous_cmd_hub.opt_args[j].opt = cmd_hub->opt_args[i].opt;
				previous_cmd_hub.opt_args[j].args = cmd_hub->opt_args[i].args;
				j++;
				previous_cmd_hub.cmd_cnt += 1;
			} else if (cmd_hub->opt_args[i].opt == 'i') {
				latency_cmd_hub.opt_args[k].opt = cmd_hub->opt_args[i].opt;
				latency_cmd_hub.opt_args[k].args = cmd_hub->opt_args[i].args;
				k++;
				latency_cmd_hub.cmd_cnt += 1;
			} else {
				medium_cmd_hub.opt_args[m].opt = cmd_hub->opt_args[i].opt;
				medium_cmd_hub.opt_args[m].args = cmd_hub->opt_args[i].args;
				m++;
				medium_cmd_hub.cmd_cnt += 1;
			}

		}
	}
	total_cmd_cnt = cmd_hub->cmd_cnt;

	/*
	 * To do all the command line.......
	 */
	if (previous_cmd_hub.cmd_cnt) {
		for (i = 0; i < previous_cmd_hub.cmd_cnt; i++) {
			callback_cmd_handle(previous_cmd_hub.opt_args[i].opt, previous_cmd_hub.opt_args[i].args);
		}
	}
	if (medium_cmd_hub.cmd_cnt) {
		for (i = 0; i < medium_cmd_hub.cmd_cnt; i++) {
			callback_cmd_handle(medium_cmd_hub.opt_args[i].opt, medium_cmd_hub.opt_args[i].args);
		}
	}
	if (latency_cmd_hub.cmd_cnt) {
		for (i = 0; i < latency_cmd_hub.cmd_cnt; i++) {
			callback_cmd_handle(latency_cmd_hub.opt_args[i].opt, latency_cmd_hub.opt_args[i].args);
		}
	}

	clear_cmd_hub(cmd_hub);
	return total_cmd_cnt;
}

static int do_user_cmd(int argc, char **argv)
{
	int have_exc_cm_cnt = 0;
	struct cncmd_hub cmd_hub;

	cmd_hub.cmd_cnt = 0;
	if (prepare_cmd(argc, argv, &cmd_hub)) {
		printf("Can not prepare command Press any will use default parameters test.\n");
		getchar();
		goto LABEL_END;
	}

	have_exc_cm_cnt = excute_cmd(&cmd_hub);
LABEL_END:
	return have_exc_cm_cnt;
}

static int callback_cmd_handle(int opt, char *args)
{
	int cmd_index;

	cmd_index = serach_lut_cmd(opt);
	if (cmd_index >= 0) {
		//printf("Call back %d handle : %s", cmd_index, rit_lut_cmd[cmd_index].cmd_usage);
		if (rit_lut_cmd[cmd_index].cmd_handle != NULL) {
			rit_lut_cmd[cmd_index].cmd_handle(args);
		} else {
			printf("THIS cmd_handle is NULL.\n");
		}
	}

	return cmd_index;
}

static int clear_cmd_hub(struct cncmd_hub *cmd_hub)
{
	int i = 0;
	if (cmd_hub->cmd_cnt) {
		for (i = 0; i < cmd_hub->cmd_cnt; i++) {
			if (cmd_hub->opt_args[i].args) {
				free(cmd_hub->opt_args[i].args);
			}
		}
		cmd_hub->cmd_cnt = 0;
	}

	return i;
}

static int prepare_cmd(int argc, char **argv, struct cncmd_hub *cmd_hub)
{
	int result = 0;
	int i = 0;
	char *temp_char = NULL;
	int opt;
	int option_index = 0;

	while ((opt = getopt_long_only(argc, argv, opt_string, long_options, &option_index)) != -1) {
		//printf("opt = %c\n", opt);
		//printf("optarg = %s\n", optarg);
		//printf("optind = %d\n", optind);
		//printf("argv[optind-1] = %s\n", argv[optind - 1]);

		//printf("option_index = %d\n", option_index);
		if (opt == '?') {
			printf("Command line analysis meet error!\n");
			result = CMD_LINE_FAILED;
			clear_cmd_hub(cmd_hub);
			break;
		}
		if (optarg) {
			//printf("cmd %c has args [%s].\n", opt, optarg);
			temp_char = NULL;
			temp_char = (char *)malloc(strlen(optarg) * 2);
			if (!temp_char) {
				printf("Can not get memory for command args!\n");
				result = MALLOC_FAILED;
				clear_cmd_hub(cmd_hub);
				break;
			}
			strcpy(temp_char, optarg);
			cmd_hub->opt_args[i].args = temp_char;
		} else {
			cmd_hub->opt_args[i].args = NULL;
		}
		cmd_hub->opt_args[i].opt = opt;
		i++;
		cmd_hub->cmd_cnt += 1;
		if (i >= CMD_NUM_MAX) {
			break;
		}
	}

	return result;

}

static int serach_lut_cmd(int opt)
{
	int  cmd_index = -1;
	int  i;
	int lut_num = sizeof(rit_lut_cmd) / sizeof(struct cnlut_cmd);

	for (i = 0; i < lut_num; i++) {
		if (opt == rit_lut_cmd[i].opt) {
			cmd_index = i;
			break;
		}
	}

	return cmd_index;
}

static int help_handle(char *args)
{
	unsigned i;

	printf("Help Info:\n");
	for (i = 0; i < sizeof(rit_lut_cmd) / sizeof(rit_lut_cmd[0]); i++) {
		printf("%s", rit_lut_cmd[i].cmd_usage);
	}
	printf("\n");

	exit(0);
}

static int version_handle(char *args)
{
	printf("version : %s\n", g_version);
	exit(0);
}

static int timecnt_handle(char *args)
{
	g_time_cnt = strtoul(args, NULL, 0);

	return 0;
}

static int list_handle(char *args)
{
	int i;

	printf("CaseList:\n");
	for (i = 0; i < sizeof(g_case_config_tbl) / sizeof(struct case_config_s); i++) {
		if (g_case_config_tbl[i].idx < 0) {
			break; //ARRIVE END MARK
		}

		if (g_case_config_tbl[i].name && g_case_config_tbl[i].selected) {
			printf("[%02d] %-18s: %s\n", i, g_case_config_tbl[i].name,
				g_case_config_tbl[i].cmdstr);
		}
	}
	printf("\n");

	exit(0);

	return 0;
}

static int filter_handle(char *args)
{
	int i;
	char filter[512] = {0};
	char name[64] = {0};

	sprintf(filter, ";%s", args);
	for (i = 0; i < sizeof(g_case_config_tbl) / sizeof(struct case_config_s); i++) {
		if (g_case_config_tbl[i].name && g_case_config_tbl[i].selected) {
			sprintf(name, ";%s", g_case_config_tbl[i].name);
			if (!strstr(filter, name)) {
				g_case_config_tbl[i].selected = 0;
			} else {
				g_case_config_tbl[i].selected = 1;
			}
		}
	}

	return 0;
}

static int erraction_handle(char *args)
{
	snprintf(g_error_action, 32, "%s", args);

	return 0;
}

static int plugincfg_handle(char *args)
{
	snprintf(g_plugincfg_path, 256, "%s", args);

	init_case_config();

	return 0;
}
/***
 * thread control
 */
static void sig_int(int signo)
{
	exit(255);
}

static int thread_init(void)  //Init thread_control if need
{
	int ret = 0;

	g_time_arrive = 0;
	// TO ADD Your logic about dynamic init thread_control
	// THE [0] and [CTL_MAX_CNT - 1] shall not be changed!!!!!!
	if (init_thread_control() <= 0) {
		printf("\nNo access case can be tested. Please check your cmdline.\n\n");
		exit(-1);
	}

	return ret;
}

static int thread_manual_clean(void)
{
	struct thread_control_s *ctl = thread_control;
	int ret;

	while (ctl->name) {
		if (!strstr(ctl->name, "loop_watch")) {
			ret = pthread_kill(ctl->id, 0);
			if (ret != ESRCH && ret != EINVAL) {
				//printf("\n\tstop %s for time arrivei.\n", ctl->name);
				pthread_kill(ctl->id, SIGRTMIN + ctl->signum);
			}
		}
		ctl++;
	}
}

static int thread_go(void)
{
	struct thread_control_s *ctl = thread_control;
	struct thread_control_s *loop_watch_ctl = thread_control;
	int meet_error = 0;

	//Create...
	while (ctl->name) {
		pthread_create(&ctl->id, NULL, ctl->entry,
			(void *)ctl->param);
		ctl++;
	}

	//Join...
	ctl = thread_control;
	ctl++;
	while (ctl->name) {
		pthread_join(ctl->id, (void **)&ctl->retval);
		if (ctl->retval) {
			meet_error++;
		}
		ctl++;
	}
	if (meet_error) {
		STOP_WATCH();
	}

	pthread_join(loop_watch_ctl->id, (void **)&loop_watch_ctl->retval);

	return 0;
}

static int thread_result_show(void)
{
	int ret = 0;
	int ret_tmp = 0;
	struct thread_control_s *ctl = thread_control;

	printf("\nResult List:\n");
	while (ctl->name) {
		if (ctl->retval_parse) {
			ret_tmp = ctl->retval_parse(ctl->retval);
			printf("\t%s : RET=%d\n", ctl->name, ret_tmp);
			ret += ret_tmp;
		}
		ctl++;
	}

	return ret;
}

static void *loop_watch(void *arg)
{
	long sec_cnt = 0;

	gettimeofday(&g_start_time, NULL);
	START_WATCH();
	signal(SIGINT, sig_int);
	printf("Looping time calc start ..... [%ld]\n", g_time_cnt);
	while (1) {
		gettimeofday(&g_current_time, NULL);

		if (((g_current_time.tv_sec - g_start_time.tv_sec) / 60) >= g_time_cnt) {
			thread_manual_clean();
			g_time_arrive = 1;
			break;
		}
		sleep(1);
		//printf("Has loop running ... %d\n", ++sec_cnt);
		printf(".");
		fflush(stdout);
		if (!(++sec_cnt % 60)) {
			printf("\n");
		}

		if (g_force_stop_watch) {
			break;
		}
	}
	printf("Looping time calc stop.\n");
	return NULL;
}

static int is_test_arrive_end(volatile long *loop_done, long finish)
{
	if (loop_done) {
		if (*loop_done < g_loop_cnt) {
			*loop_done += finish;
		}
		if (g_time_arrive && *loop_done >= g_loop_cnt) {
			return 1;
		}
	} else {
		if (g_time_arrive) {
			return 1;
		}
	}

	return 0;
}

static int init_case_config(void)
{
	FILE *fp = NULL;
	int ret = 0;
	char line[1024];
	int i = 0;
	char *token = NULL;
	char *next_token = NULL;
	int len;

	fp = fopen(g_plugincfg_path, "r");
	if (!fp) {
		printf("Can not open [%s] lead FAILED\n", g_plugincfg_path);
		ret = -1;
		goto LABEL_EXIT;
	} else {
		while (fgets(line, sizeof(line), fp) != NULL) {
			if ((strstr(line, "#") && line[0] == '#') ||
			    (!strstr(line, "case_"))) {
				continue;
			}

			/*delele enter.ch*/
			len = strlen(line);
			line[len - 1] = '\0';

			token = strtok_r(line, ":", &next_token);
			snprintf(g_case_config_tbl[i].name, NAME_LEN, "%s", token);
			snprintf(g_case_config_tbl[i].cmdstr, CMDSTR_LEN, "%s", next_token);
			g_case_config_tbl[i].idx = i;
			g_case_config_tbl[i].selected = 1;
			i++;
			if (i >= CASE_MAX_CNT) {
				break;
			}
		}
	}
	fclose(fp);

LABEL_EXIT:
	g_case_config_tbl[i].idx = -1; /*ADD END MARK*/

	return ret;
}

static int init_thread_control(void)
{
	int ret = 0;
	int i = 1; /*JumpPass loop_watch*/
	int index = 0;

	for (index = 0; index < CASE_MAX_CNT; index++) {
		if (g_case_config_tbl[index].idx >= 0) {
			if (g_case_config_tbl[index].selected) {
				thread_control[i].name = g_case_config_tbl[index].name;
				thread_control[i].param = (void *)(long)(index);
				thread_control[i].entry = common_case_entry;
				thread_control[i].retval_parse = common_case_retval_parse;
				thread_control[i].signum = index;
				i++;
			}
		} else {
			break;
		}
	}

	return (i - 1); /*How many test thread*/
}
//================================== TEST CASEs
static void sighandler(int signum)
{
	//TO ADD

	pthread_exit(0);
}

static void *common_case_entry(void *arg)
{
	int ret = 0;
	char buff[1024];
	char log_name[64];
	long index = (long)arg;
	FILE *stream = NULL;
	FILE *fp_log = NULL;

	signal(index + SIGRTMIN, sighandler);
	snprintf(log_name, 64, "rcd%ld-%s.log", index, g_case_config_tbl[index].name);
	fp_log = fopen(log_name, "w");

LABEL_RETRY:
	stream = popen(g_case_config_tbl[index].cmdstr, "r");
	if (!stream) {
		printf("case[%s] popen [%s] lead FAILED\n",
			g_case_config_tbl[index].name,
			g_case_config_tbl[index].cmdstr);
	} else {
		while (fgets(buff, sizeof(buff), stream) != NULL) {
			if (fp_log) {
				fprintf(fp_log, "%s", buff);
				fflush(fp_log);
			}
			if (strstr(buff, "FAIL") ||
			    strstr(buff, "fail") ||
			    strstr(buff, "ERROR") ||
			    strstr(buff, "error")) {
			    	ret = -1;
				if (!fp_log) {
					printf("[%s] : %s\n", g_case_config_tbl[index].name, buff);
					fflush(stdout);
				}
				goto LABEL_EXIT;
			}
		}
	}
	if (!is_test_arrive_end(NULL, 0)) {
		ret = pclose(stream);
		stream = NULL;
		if (!ret) {
			goto LABEL_RETRY;
		}
	}

LABEL_EXIT:
	if (stream) {
		pclose(stream);
	}
	if (fp_log) {
		fclose(fp_log);
	}

	thread_call_check_exit((int)index, g_case_config_tbl[index].name, ret);

	return (void *)(long)ret;
}

static unsigned long common_case_retval_parse(void *retval)
{
	return (unsigned long)retval;
}
