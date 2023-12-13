create table users
(
    id       serial primary key,
    username varchar unique,
    password varchar
);

