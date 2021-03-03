#ifndef _TAP_H_
#define _TAP_H_

int activate_tap(int s, char *name);
int add_to_bridge(int s, char *bridge, char *tap);
int create_tap(int s, char **name);
int destroy_tap(int s, char *name);

#endif
