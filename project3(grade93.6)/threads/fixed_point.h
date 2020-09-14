#ifndef THREADS_FIXED_POINT_H
#define THREADS_FIXED_POINT_H

typedef int fixed_point_t;

#define F (1<<14)

#define CONVERT_N_TO_FIXED(N) ((N)*(F))
#define ROUND_TO_ZERO(X) ((X)/(F))
#define ROUND_TO_NEAR(X) (((X)>=0) ? (((X)+((F)/2))/(F)) : (((X)-((F)/2))/(F)))

#define ADD_X_Y(X, Y) ((X)+(Y))
#define SUBTRACT_X_Y(X, Y) ((X)-(Y))
#define ADD_X_N(X, N) ((X)+((N)*(F)))
#define SUBTRACT_X_N(X, N) ((X)-((N)*(F)))
#define MULT_X_Y(X, Y) ((((int64_t)(X))*(Y))/(F))
#define MULT_X_N(X, N) ((X)*(N))
#define DIV_X_Y(X, Y) ((((int64_t)(X))*(F))/(Y))
#define DIV_X_N(X, N) ((X)/(N))

#endif
