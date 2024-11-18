#ifndef STATISTICS_H
#define STATISTICS_H

#include "isa-top.h"

int compare_bytes(const void *a, const void *b);
int compare_packets(const void *a, const void *b);
void display_statistics();

#endif // STATISTICS_H