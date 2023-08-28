#include <sys/nv.h>
#include <sys/fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <assert.h>

#include "../conf.h"

static void
null0(nvlist_t *a, nvlist_t *b)
{
	nvlist_add_null(a, "key0");
	assert(compare_nvlist(a, b) > 0);
}

static void
null1(nvlist_t *a, nvlist_t *b)
{
	nvlist_add_null(b, "key0");
	assert(compare_nvlist(a, b) < 0);
}

static void
null2(nvlist_t *a, nvlist_t *b)
{
	nvlist_add_null(a, "key0");
	nvlist_add_null(b, "key0");
	assert(compare_nvlist(a, b) == 0);
}

static void
bool0(nvlist_t *a, nvlist_t *b)
{
	nvlist_add_bool(a, "key0", true);
	assert(compare_nvlist(a, b) > 0);
}

static void
bool1(nvlist_t *a, nvlist_t *b)
{
	nvlist_add_bool(a, "key0", true);
	nvlist_add_bool(b, "key0", true);
	nvlist_add_bool(a, "key2", false);
	nvlist_add_bool(b, "key2", false);
	assert(compare_nvlist(a, b) == 0);
}

static void
bool2(nvlist_t *a, nvlist_t *b)
{
	nvlist_add_bool(a, "key1", true);
	nvlist_add_bool(b, "key1", false);
	assert(compare_nvlist(a, b) > 0);
}

static void
bool3(nvlist_t *a, nvlist_t *b)
{
	nvlist_add_bool(a, "key1", false);
	nvlist_add_bool(b, "key1", true);
	assert(compare_nvlist(a, b) < 0);
}

static void
bool4(nvlist_t *a, nvlist_t *b)
{
	nvlist_add_bool(b, "key0", true);
	assert(compare_nvlist(a, b) < 0);
}

static void
num0(nvlist_t *a, nvlist_t *b)
{
	nvlist_add_number(a, "key0", 10);
	assert(compare_nvlist(a, b) > 0);
}

static void
num1(nvlist_t *a, nvlist_t *b)
{
	nvlist_add_number(b, "key0", 10);
	assert(compare_nvlist(a, b) < 0);
}

static void
num2(nvlist_t *a, nvlist_t *b)
{
	nvlist_add_number(a, "key0", 10);
	nvlist_add_number(b, "key0", 10);
	assert(compare_nvlist(a, b) == 0);
}

static void
num3(nvlist_t *a, nvlist_t *b)
{
	nvlist_add_number(a, "key1", 20);
	nvlist_add_number(b, "key1", 10);
	assert(compare_nvlist(a, b) > 0);
}

static void
num4(nvlist_t *a, nvlist_t *b)
{
	nvlist_add_number(a, "key1", 10);
	nvlist_add_number(b, "key1", 20);
	assert(compare_nvlist(a, b) < 0);
}


static void
str0(nvlist_t *a, nvlist_t *b)
{
	nvlist_add_string(a, "key0", "aaa");
	assert(compare_nvlist(a, b) > 0);
}

static void
str1(nvlist_t *a, nvlist_t *b)
{
	nvlist_add_string(b, "key0", "aaa");
	assert(compare_nvlist(a, b) < 0);
}

static void
str2(nvlist_t *a, nvlist_t *b)
{
	nvlist_add_string(a, "key0", "aaa");
	nvlist_add_string(b, "key0", "aaa");
	assert(compare_nvlist(a, b) == 0);
}

static void
str3(nvlist_t *a, nvlist_t *b)
{
	nvlist_add_string(a, "key0", "aaa");
	nvlist_add_string(b, "key0", "bbb");
	assert(compare_nvlist(a, b) < 0);
}

static void
str4(nvlist_t *a, nvlist_t *b)
{
	nvlist_add_string(a, "key0", "bbb");
	nvlist_add_string(b, "key0", "aaa");
	assert(compare_nvlist(a, b) > 0);
}

static void
str5(nvlist_t *a, nvlist_t *b)
{
	nvlist_add_string(a, "key0", "aaaa");
	nvlist_add_string(b, "key0", "aaa");
	assert(compare_nvlist(a, b) > 0);
}

static void
str6(nvlist_t *a, nvlist_t *b)
{
	nvlist_add_string(a, "key0", "aaa");
	nvlist_add_string(b, "key0", "aaaa");
	assert(compare_nvlist(a, b) < 0);
}

static void
str7(nvlist_t *a, nvlist_t *b)
{
	/* Adding NULL pointer makes nvlist to error state. */
	nvlist_add_string(b, "key2", NULL);
	assert(compare_nvlist(a, b) > 0);
	nvlist_add_string(a, "key2", NULL);
	assert(compare_nvlist(a, b) < 0);
}

static void
nvl0(nvlist_t *a, nvlist_t *b)
{
	nvlist_t *c = nvlist_create(0);
	nvlist_t *d = nvlist_create(0);

	nvlist_add_nvlist(a, "list0", c);
	assert(compare_nvlist(a, b) > 0);

	nvlist_destroy(c);
	nvlist_destroy(d);
}

static void
nvl1(nvlist_t *a, nvlist_t *b)
{
	nvlist_t *c = nvlist_create(0);
	nvlist_t *d = nvlist_create(0);

	nvlist_add_nvlist(b, "list0", c);
	assert(compare_nvlist(a, b) < 0);

	nvlist_destroy(c);
	nvlist_destroy(d);
}

static void
nvl2(nvlist_t *a, nvlist_t *b)
{
	nvlist_t *c = nvlist_create(0);
	nvlist_t *d = nvlist_create(0);

	nvlist_add_number(c, "key0", 10);
	nvlist_add_number(d, "key0", 10);
	nvlist_add_nvlist(a, "list0", c);
	nvlist_add_nvlist(b, "list0", d);
	assert(compare_nvlist(a, b) == 0);

	nvlist_destroy(c);
	nvlist_destroy(d);
}

static void
nvl3(nvlist_t *a, nvlist_t *b)
{
	nvlist_t *c = nvlist_create(0);
	nvlist_t *d = nvlist_create(0);

	nvlist_add_number(c, "key0", 10);
	nvlist_add_number(d, "key0", 20);
	nvlist_add_nvlist(a, "list0", c);
	nvlist_add_nvlist(b, "list0", d);
	assert(compare_nvlist(a, b) < 0);

	nvlist_destroy(c);
	nvlist_destroy(d);
}

static void
nvl4(nvlist_t *a, nvlist_t *b)
{
	nvlist_t *c = nvlist_create(0);
	nvlist_t *d = nvlist_create(0);

	nvlist_add_number(c, "key0", 20);
	nvlist_add_number(d, "key0", 10);
	nvlist_add_nvlist(a, "list0", c);
	nvlist_add_nvlist(b, "list0", d);
	assert(compare_nvlist(a, b) > 0);

	nvlist_destroy(c);
	nvlist_destroy(d);
}

static void
dsc0(nvlist_t *a, nvlist_t *b)
{
	int fd = open("/dev/null", O_RDWR);

	nvlist_add_descriptor(a, "key0", fd);
	assert(compare_nvlist(a, b) > 0);

	close(fd);
}

static void
dsc1(nvlist_t *a, nvlist_t *b)
{
	int fd = open("/dev/null", O_RDWR);

	nvlist_add_descriptor(b, "key0", fd);
	assert(compare_nvlist(a, b) < 0);

	close(fd);
}

static void
dsc2(nvlist_t *a, nvlist_t *b)
{
	int fd = open("/dev/null", O_RDWR);

	nvlist_add_descriptor(a, "key0", fd);
	nvlist_add_descriptor(b, "key0", fd);
	assert(compare_nvlist(a, b) < 0);

	close(fd);
}

static void
dsc3(nvlist_t *a, nvlist_t *b)
{
	int fd = open("/dev/null", O_RDWR);

	nvlist_add_descriptor(b, "key0", fd);
	nvlist_add_descriptor(a, "key0", fd);
	assert(compare_nvlist(a, b) > 0);

	close(fd);
}

static void
bin0(nvlist_t *a, nvlist_t *b)
{
	nvlist_add_binary(a, "key0", "aaa", 3);
	assert(compare_nvlist(a, b) > 0);
}

static void
bin1(nvlist_t *a, nvlist_t *b)
{
	nvlist_add_binary(b, "key0", "aaa", 3);
	assert(compare_nvlist(a, b) < 0);
}

static void
bin2(nvlist_t *a, nvlist_t *b)
{
	nvlist_add_binary(a, "key0", "aaa", 3);
	nvlist_add_binary(b, "key0", "aaa", 3);
	assert(compare_nvlist(a, b) == 0);
}

static void
bin3(nvlist_t *a, nvlist_t *b)
{
	nvlist_add_binary(a, "key0", "aaa", 3);
	nvlist_add_binary(b, "key0", "bbb", 3);
	assert(compare_nvlist(a, b) < 0);
}

static void
bin4(nvlist_t *a, nvlist_t *b)
{
	nvlist_add_binary(a, "key0", "bbb", 3);
	nvlist_add_binary(b, "key0", "aaa", 3);
	assert(compare_nvlist(a, b) > 0);
}

static void
bin5(nvlist_t *a, nvlist_t *b)
{
	nvlist_add_binary(a, "key0", "aaaa", 4);
	nvlist_add_binary(b, "key0", "aaa", 3);
	assert(compare_nvlist(a, b) > 0);
}

static void
bin6(nvlist_t *a, nvlist_t *b)
{
	nvlist_add_binary(a, "key0", "aaa", 3);
	nvlist_add_binary(b, "key0", "aaaa", 4);
	assert(compare_nvlist(a, b) < 0);
}

static void
bin7(nvlist_t *a, nvlist_t *b)
{
	/* Adding NULL pointer makes nvlist to error state. */
	nvlist_add_binary(b, "key2", NULL, 0);
	assert(compare_nvlist(a, b) > 0);
	nvlist_add_binary(a, "key2", NULL, 0);
	assert(compare_nvlist(a, b) < 0);
}

static void
barr0(nvlist_t *a, nvlist_t *b)
{
	static bool da[] = { true, true, true };
	nvlist_add_bool_array(a, "key0", da, 3);
	assert(compare_nvlist(a, b) > 0);
}

static void
barr1(nvlist_t *a, nvlist_t *b)
{
	static bool da[] = { true, true, true };
	nvlist_add_bool_array(b, "key0", da, 3);
	assert(compare_nvlist(a, b) < 0);
}

static void
barr2(nvlist_t *a, nvlist_t *b)
{
	static bool da[] = { true, true, true };
	nvlist_add_bool_array(a, "key0", da, 3);
	nvlist_add_bool_array(b, "key0", da, 3);
	assert(compare_nvlist(a, b) == 0);
}

static void
barr3(nvlist_t *a, nvlist_t *b)
{
	static bool da[] = { true, true, true };
	static bool db[] = { true, false, false };
	nvlist_add_bool_array(a, "key0", da, 3);
	nvlist_add_bool_array(b, "key0", db, 3);
	assert(compare_nvlist(a, b) > 0);
}

static void
barr4(nvlist_t *a, nvlist_t *b)
{
	static bool da[] = { true, true, true };
	static bool db[] = { true, false, false };
	nvlist_add_bool_array(a, "key0", db, 3);
	nvlist_add_bool_array(b, "key0", da, 3);
	assert(compare_nvlist(a, b) < 0);
}

static void
barr5(nvlist_t *a, nvlist_t *b)
{
	static bool da[] = { true, true, true };
	static bool db[] = { true, false, false };
	nvlist_add_bool_array(a, "key0", db, 3);
	nvlist_add_bool_array(b, "key0", da, 2);
	assert(compare_nvlist(a, b) < 0);
}

static void
barr6(nvlist_t *a, nvlist_t *b)
{
	static bool da[] = { true, true, true };
	static bool db[] = { true, false, false };
	nvlist_add_bool_array(a, "key0", db, 2);
	nvlist_add_bool_array(b, "key0", da, 3);
	assert(compare_nvlist(a, b) < 0);
}

static void
barr7(nvlist_t *a, nvlist_t *b)
{
	static bool da[] = { true, true, true };
	nvlist_add_bool_array(a, "key0", da, 2);
	nvlist_add_bool_array(b, "key0", da, 3);
	assert(compare_nvlist(a, b) < 0);
}

static void
barr8(nvlist_t *a, nvlist_t *b)
{
	static bool da[] = { true, true, true };
	nvlist_add_bool_array(a, "key0", da, 3);
	nvlist_add_bool_array(b, "key0", da, 2);
	assert(compare_nvlist(a, b) > 0);
}

static void
narr0(nvlist_t *a, nvlist_t *b)
{
	static uint64_t da[] = { 10, 20, 30 };
	nvlist_add_number_array(a, "key0", da, 3);
	assert(compare_nvlist(a, b) > 0);
}

static void
narr1(nvlist_t *a, nvlist_t *b)
{
	static uint64_t da[] = { 10, 20, 30 };
	nvlist_add_number_array(b, "key0", da, 3);
	assert(compare_nvlist(a, b) < 0);
}

static void
narr2(nvlist_t *a, nvlist_t *b)
{
	static uint64_t da[] = { 10, 20, 30 };
	nvlist_add_number_array(a, "key0", da, 3);
	nvlist_add_number_array(b, "key0", da, 3);
	assert(compare_nvlist(a, b) == 0);
}

static void
narr3(nvlist_t *a, nvlist_t *b)
{
	static uint64_t da[] = { 10, 20, 30 };
	static uint64_t db[] = { 10, 0, -10 };
	nvlist_add_number_array(a, "key0", da, 3);
	nvlist_add_number_array(b, "key0", db, 3);
	assert(compare_nvlist(a, b) > 0);
}

static void
narr4(nvlist_t *a, nvlist_t *b)
{
	static uint64_t da[] = { 10, 20, 30 };
	static uint64_t db[] = { 10, 0, 0 };
	nvlist_add_number_array(a, "key0", db, 3);
	nvlist_add_number_array(b, "key0", da, 3);
	assert(compare_nvlist(a, b) < 0);
}

static void
narr5(nvlist_t *a, nvlist_t *b)
{
	static uint64_t da[] = { 10, 20, 30 };
	static uint64_t db[] = { 10, 0, 0 };
	nvlist_add_number_array(a, "key0", da, 2);
	nvlist_add_number_array(b, "key0", db, 3);
	assert(compare_nvlist(a, b) > 0);
}

static void
narr6(nvlist_t *a, nvlist_t *b)
{
	static uint64_t da[] = { 10, 20, 30 };
	static uint64_t db[] = { 10, 0, 0 };
	nvlist_add_number_array(a, "key0", db, 3);
	nvlist_add_number_array(b, "key0", da, 2);
	assert(compare_nvlist(a, b) < 0);
}

static void
narr7(nvlist_t *a, nvlist_t *b)
{
	static uint64_t da[] = { 10, 20, 30 };
	nvlist_add_number_array(a, "key0", da, 2);
	nvlist_add_number_array(b, "key0", da, 3);
	assert(compare_nvlist(a, b) < 0);
}

static void
narr8(nvlist_t *a, nvlist_t *b)
{
	static uint64_t da[] = { 10, 20, 30 };
	nvlist_add_number_array(a, "key0", da, 3);
	nvlist_add_number_array(b, "key0", da, 2);
	assert(compare_nvlist(a, b) > 0);
}

static void
sarr0(nvlist_t *a, nvlist_t *b)
{
	static const char *da[] = { "aaa", "bbb", "ccc"};
	nvlist_add_string_array(a, "key0", da, 3);
	assert(compare_nvlist(a, b) > 0);
}

static void
sarr1(nvlist_t *a, nvlist_t *b)
{
	static const char *da[] = { "aaa", "bbb", "ccc"};
	nvlist_add_string_array(b, "key0", da, 3);
	assert(compare_nvlist(a, b) < 0);
}

static void
sarr2(nvlist_t *a, nvlist_t *b)
{
	static const char *da[] = { "aaa", "bbb", "ccc"};
	nvlist_add_string_array(a, "key0", da, 3);
	nvlist_add_string_array(b, "key0", da, 3);
	assert(compare_nvlist(a, b) == 0);
}

static void
sarr3(nvlist_t *a, nvlist_t *b)
{
	static const char *da[] = { "aaa", "bbb", "ccc"};
	static const char *db[] = { "aaa", "aaa", "bbb"};
	nvlist_add_string_array(a, "key0", da, 3);
	nvlist_add_string_array(b, "key0", db, 3);
	assert(compare_nvlist(a, b) > 0);
}

static void
sarr4(nvlist_t *a, nvlist_t *b)
{
	static const char *da[] = { "aaa", "bbb", "ccc"};
	static const char *db[] = { "aaa", "aaa", "bbb"};
	nvlist_add_string_array(a, "key0", db, 3);
	nvlist_add_string_array(b, "key0", da, 3);
	assert(compare_nvlist(a, b) < 0);
}

static void
sarr5(nvlist_t *a, nvlist_t *b)
{
	static const char *da[] = { "aaa", "bbb", "ccc"};
	static const char *db[] = { "aaa", "aaa", "bbb"};
	nvlist_add_string_array(a, "key0", da, 2);
	nvlist_add_string_array(b, "key0", db, 3);
	assert(compare_nvlist(a, b) > 0);
}

static void
sarr6(nvlist_t *a, nvlist_t *b)
{
	static const char *da[] = { "aaa", "bbb", "ccc"};
	static const char *db[] = { "aaa", "aaa", "bbb"};
	nvlist_add_string_array(a, "key0", db, 3);
	nvlist_add_string_array(b, "key0", da, 2);
	assert(compare_nvlist(a, b) < 0);
}

static void
sarr7(nvlist_t *a, nvlist_t *b)
{
	static const char *da[] = { "aaa", "bbb", "ccc"};
	nvlist_add_string_array(a, "key0", da, 2);
	nvlist_add_string_array(b, "key0", da, 3);
	assert(compare_nvlist(a, b) < 0);
}

static void
sarr8(nvlist_t *a, nvlist_t *b)
{
	static const char *da[] = { "aaa", "bbb", "ccc"};
	nvlist_add_string_array(a, "key0", da, 3);
	nvlist_add_string_array(b, "key0", da, 2);
	assert(compare_nvlist(a, b) > 0);
}

static void
nvarr0(nvlist_t *a, nvlist_t *b)
{
	int i;
	nvlist_t *t;
	const nvlist_t *da[3];

	for (i = 0; i < sizeof(da)/sizeof(da[0]); i++) {
		t = nvlist_create(0);
		nvlist_add_number(t, "key0", 10);
		da[i] = t;
	}

	nvlist_add_nvlist_array(a, "list0", da, 3);
	assert(compare_nvlist(a, b) > 0);

	for (i = 0; i < sizeof(da)/sizeof(da[0]); i++)
		nvlist_destroy((nvlist_t *)da[i]);
}

static void
nvarr1(nvlist_t *a, nvlist_t *b)
{
	int i;
	nvlist_t *t;
	const nvlist_t *da[3];

	for (i = 0; i < sizeof(da)/sizeof(da[0]); i++) {
		t = nvlist_create(0);
		nvlist_add_number(t, "key0", 10);
		da[i] = t;
	}

	nvlist_add_nvlist_array(b, "list0", da, 3);
	assert(compare_nvlist(a, b) < 0);

	for (i = 0; i < sizeof(da)/sizeof(da[0]); i++)
		nvlist_destroy((nvlist_t *)da[i]);
}

static void
nvarr2(nvlist_t *a, nvlist_t *b)
{
	int i;
	nvlist_t *t;
	const nvlist_t *da[3];

	for (i = 0; i < sizeof(da)/sizeof(da[0]); i++) {
		t = nvlist_create(0);
		nvlist_add_number(t, "key0", 10);
		da[i] = t;
	}

	nvlist_add_nvlist_array(a, "list0", da, 3);
	nvlist_add_nvlist_array(b, "list0", da, 3);
	assert(compare_nvlist(a, b) == 0);

	for (i = 0; i < sizeof(da)/sizeof(da[0]); i++)
		nvlist_destroy((nvlist_t *)da[i]);
}

static void
nvarr3(nvlist_t *a, nvlist_t *b)
{
	int i;
	nvlist_t *t;
	const nvlist_t *da[3], *db[3];

	for (i = 0; i < sizeof(da)/sizeof(da[0]); i++) {
		t = nvlist_create(0);
		nvlist_add_number(t, "key0", 10 + i);
		da[i] = t;
	}

	for (i = 0; i < sizeof(db)/sizeof(db[0]); i++) {
		t = nvlist_create(0);
		nvlist_add_number(t, "key0", 10 - i);
		db[i] = t;
	}

	nvlist_add_nvlist_array(a, "list0", da, 3);
	nvlist_add_nvlist_array(b, "list0", db, 3);
	assert(compare_nvlist(a, b) > 0);

	for (i = 0; i < sizeof(da)/sizeof(da[0]); i++)
		nvlist_destroy((nvlist_t *)da[i]);
	for (i = 0; i < sizeof(db)/sizeof(db[0]); i++)
		nvlist_destroy((nvlist_t *)db[i]);
}

static void
nvarr4(nvlist_t *a, nvlist_t *b)
{
	int i;
	nvlist_t *t;
	const nvlist_t *da[3], *db[3];

	for (i = 0; i < sizeof(da)/sizeof(da[0]); i++) {
		t = nvlist_create(0);
		nvlist_add_number(t, "key0", 10 + i);
		da[i] = t;
	}

	for (i = 0; i < sizeof(db)/sizeof(db[0]); i++) {
		t = nvlist_create(0);
		nvlist_add_number(t, "key0", 10 - i);
		db[i] = t;
	}

	nvlist_add_nvlist_array(a, "list0", db, 3);
	nvlist_add_nvlist_array(b, "list0", da, 3);
	assert(compare_nvlist(a, b) < 0);

	for (i = 0; i < sizeof(da)/sizeof(da[0]); i++)
		nvlist_destroy((nvlist_t *)da[i]);
	for (i = 0; i < sizeof(db)/sizeof(db[0]); i++)
		nvlist_destroy((nvlist_t *)db[i]);
}

static void
nvarr5(nvlist_t *a, nvlist_t *b)
{
	int i;
	nvlist_t *t;
	const nvlist_t *da[2], *db[3];

	for (i = 0; i < sizeof(da)/sizeof(da[0]); i++) {
		t = nvlist_create(0);
		nvlist_add_number(t, "key0", 10 + i);
		da[i] = t;
	}

	for (i = 0; i < sizeof(db)/sizeof(db[0]); i++) {
		t = nvlist_create(0);
		nvlist_add_number(t, "key0", 10 - i);
		db[i] = t;
	}

	nvlist_add_nvlist_array(a, "list0", da, 2);
	nvlist_add_nvlist_array(b, "list0", db, 3);
	assert(compare_nvlist(a, b) > 0);

	for (i = 0; i < sizeof(da)/sizeof(da[0]); i++)
		nvlist_destroy((nvlist_t *)da[i]);
	for (i = 0; i < sizeof(db)/sizeof(db[0]); i++)
		nvlist_destroy((nvlist_t *)db[i]);
}

static void
nvarr6(nvlist_t *a, nvlist_t *b)
{
	int i;
	nvlist_t *t;
	const nvlist_t *da[2], *db[3];

	for (i = 0; i < sizeof(da)/sizeof(da[0]); i++) {
		t = nvlist_create(0);
		nvlist_add_number(t, "key0", 10 + i);
		da[i] = t;
	}

	for (i = 0; i < sizeof(db)/sizeof(db[0]); i++) {
		t = nvlist_create(0);
		nvlist_add_number(t, "key0", 10 - i);
		db[i] = t;
	}

	nvlist_add_nvlist_array(a, "list0", db, 3);
	nvlist_add_nvlist_array(b, "list0", da, 2);
	assert(compare_nvlist(a, b) < 0);

	for (i = 0; i < sizeof(da)/sizeof(da[0]); i++)
		nvlist_destroy((nvlist_t *)da[i]);
	for (i = 0; i < sizeof(db)/sizeof(db[0]); i++)
		nvlist_destroy((nvlist_t *)db[i]);
}

static void
nvarr7(nvlist_t *a, nvlist_t *b)
{
	int i;
	nvlist_t *t;
	const nvlist_t *da[3];

	for (i = 0; i < sizeof(da)/sizeof(da[0]); i++) {
		t = nvlist_create(0);
		nvlist_add_number(t, "key0", 10);
		da[i] = t;
	}

	nvlist_add_nvlist_array(a, "list0", da, 2);
	nvlist_add_nvlist_array(b, "list0", da, 3);
	assert(compare_nvlist(a, b) < 0);

	for (i = 0; i < sizeof(da)/sizeof(da[0]); i++)
		nvlist_destroy((nvlist_t *)da[i]);
}

static void
nvarr8(nvlist_t *a, nvlist_t *b)
{
	int i;
	nvlist_t *t;
	const nvlist_t *da[3];

	for (i = 0; i < sizeof(da)/sizeof(da[0]); i++) {
		t = nvlist_create(0);
		nvlist_add_number(t, "key0", 10);
		da[i] = t;
	}

	nvlist_add_nvlist_array(a, "list0", da, 3);
	nvlist_add_nvlist_array(b, "list0", da, 2);
	assert(compare_nvlist(a, b) > 0);

	for (i = 0; i < sizeof(da)/sizeof(da[0]); i++)
		nvlist_destroy((nvlist_t *)da[i]);
}

typedef void (*test_func)(nvlist_t *, nvlist_t *);
int
main(int argc, char *argv[])
{
	int i;
	nvlist_t *a, *b;
	test_func func_list[] = {
		null0, null1, null2,
		bool0,bool1,bool2,bool3,bool4,
		num0,num1,num2,num3,num4,
		str0,str1,str2,str3,str4,str5,str6,str7,
		nvl0,nvl1,nvl2,nvl3,nvl4,
		dsc0, dsc1, dsc2, dsc3,
		bin0,bin1,bin2,bin3,bin4,bin5,bin6,bin7,
		barr0,barr1,barr2,barr3,barr4,barr5,barr6, barr7, barr8,
		narr0,narr1,narr2,narr3,narr4,narr5,narr6, narr7, narr8,
		sarr0, sarr1,sarr2,sarr3,sarr4,sarr5,sarr6, sarr7, sarr8,
		nvarr0, nvarr1, nvarr2, nvarr3, nvarr4, nvarr5, nvarr6, nvarr7, nvarr8,
	};
	for (i = 0; i < sizeof(func_list)/ sizeof(func_list[0]); i++) {
		a = nvlist_create(0);
		b = nvlist_create(0);
		(*func_list[i])(a, b);
		nvlist_destroy(a);
		nvlist_destroy(b);
	}

	puts("conf_test: ok.");
	return 0;
}
