#!/bin/bash

rm -rf $HOME/var/phoenix/memfiles/*
for i in 0 1 2 3 4 5 6 7; do
    mkdir -p $HOME/var/phoenix/memfiles/$i
done
