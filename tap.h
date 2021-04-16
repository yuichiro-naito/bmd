#ifndef _TAP_H_
#define _TAP_H_

int activate_tap(int s, const char *name);
int add_to_bridge(int s, const char *bridge, const char *tap);
int create_tap(int s, char **name);
int destroy_tap(int s, const char *name);
int set_tap_description(int s, const char *tap, char *desc);
#endif
