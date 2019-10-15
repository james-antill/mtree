#! /usr/bin/perl -n

if (/^Num/ ||
    /^U:/ ||
    /^G:/ ||
    /^O:/ ||
    /^D:/ ||
    /^I:/ ||
    /^L:/ ||
    /^MO:/ ||
    /^AT:/ ||
    /^CT:/) { next }

print
