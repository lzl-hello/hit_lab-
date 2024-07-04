for file in ./lab2_test/*
    do
        echo Testing with $file
        ./parse.sh $file
    done