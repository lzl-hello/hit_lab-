for file in ./test2/*
    do
        echo Testing with $file
        ./parse.sh $file
    done