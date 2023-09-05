docker build -t pepc-boost-relay .;
docker tag pepc-boost-relay:latest public.ecr.aws/t1d5h1w5/pepc-boost-relay:latest;
docker push public.ecr.aws/t1d5h1w5/pepc-boost-relay:latest;