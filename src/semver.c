/*
 * semver.c
 *
 * Copyright (c) 2015-2017 Tomas Aparicio
 * MIT licensed
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "semver.h"

#define SLICE_SIZE   50
#define DELIMITER    "."
#define PR_DELIMITER "-"
#define MT_DELIMITER "+"
#define ANDRAX_DELIMITER "="
#define NUMBERS      "0123456789"
#define ALPHA        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
#define DELIMITERS   DELIMITER PR_DELIMITER MT_DELIMITER ANDRAX_DELIMITER
#define VALID_CHARS  NUMBERS ALPHA DELIMITERS

static const size_t MAX_SIZE     = sizeof(char) * 255;
static const int MAX_SAFE_INT = (unsigned int) -1 >> 1;


enum operators {
  SYMBOL_GT = 0x3e,
  SYMBOL_LT = 0x3c,
  SYMBOL_EQ = 0x3d,
  SYMBOL_TF = 0x7e,
  SYMBOL_CF = 0x5e
};

static int
strcut (char *str, int begin, int len) {
  size_t l;
  l = strlen(str);

  if((int)l < 0 || (int)l > MAX_SAFE_INT) return -1;

  if (len < 0) len = l - begin + 1;
  if (begin + len > (int)l) len = l - begin;
  memmove(str + begin, str + begin + len, l - len + 1 - begin);

  return len;
}

static int
contains (const char c, const char *matrix, size_t len) {
  size_t x;
  for (x = 0; x < len; x++)
    if ((char) matrix[x] == c) return 1;
  return 0;
}

static int
has_valid_chars (const char *str, const char *matrix) {
  size_t i, len, mlen;
  len = strlen(str);
  mlen = strlen(matrix);

  for (i = 0; i < len; i++)
    if (contains(str[i], matrix, mlen) == 0)
      return 0;

  return 1;
}

static int
binary_comparison (int x, int y) {
  if (x == y) return 0;
  if (x > y) return 1;
  return -1;
}

static int
parse_int (const char *s) {
  int valid, num;
  valid = has_valid_chars(s, NUMBERS);
  if (valid == 0) return -1;

  num = strtol(s, NULL, 10);
  if (num > MAX_SAFE_INT) return -1;

  return num;
}

static char *
parse_slice (char *buf, char sep) {
  char *pr, *part;
  int plen;

  pr = strchr(buf, sep);
  if (pr == NULL) return NULL;
  plen = strlen(pr);

  part = (char*)calloc(plen + 1, sizeof(*part));
  if (part == NULL) return NULL;
  memcpy(part, pr + 1, plen);
  part[plen] = '\0';

  *pr = '\0';

  return part;
}


int semver_parse (const char *str, semver_t *ver) {
  int valid, res;
  size_t len;
  char *buf;
  valid = semver_is_valid(str);
  if (!valid) return -1;

  len = strlen(str);
  buf = (char*)calloc(len + 1, sizeof(*buf));
  if (buf == NULL) return -1;
  strcpy(buf, str);

  ver->metadata = parse_slice(buf, MT_DELIMITER[0]);
  ver->prerelease = parse_slice(buf, PR_DELIMITER[0]);

  res = semver_parse_version(buf, ver);
  free(buf);
#if DEBUG > 0
  printf("[debug] semver.c %s = %d.%d.%d, %s %s\n", str, ver->major, ver->minor, ver->patch, ver->prerelease, ver->metadata);
#endif
  return res;
}

int semver_parse_version (const char *str, semver_t *ver) {
  size_t len;
  int index, value;
  char *slice, *next, *endptr;
  slice = (char *) str;
  index = 0;

  while (slice != NULL && index++ < 4) {
    next = strchr(slice, DELIMITER[0]);
    if (next == NULL)
      len = strlen(slice);
    else
      len = next - slice;
    if (len > SLICE_SIZE) return -1;

    value = strtol(slice, &endptr, 10);
    if (endptr != next && *endptr != '\0') return -1;

    switch (index) {
      case 1: ver->major = value; break;
      case 2: ver->minor = value; break;
      case 3: ver->patch = value; break;
    }

    if (next == NULL)
      slice = NULL;
    else
      slice = next + 1;
  }

  return 0;
}

static int
compare_prerelease (char *x, char *y) {
  char *lastx, *lasty, *xptr, *yptr, *endptr;
  int xlen, ylen, xisnum, yisnum, xnum, ynum;
  int xn, yn, min, res;
  if (x == NULL && y == NULL) return 0;
  if (y == NULL && x) return -1;
  if (x == NULL && y) return 1;

  lastx = x;
  lasty = y;
  xlen = strlen(x);
  ylen = strlen(y);

  while (1) {
    if ((xptr = strchr(lastx, DELIMITER[0])) == NULL)
      xptr = x + xlen;
    if ((yptr = strchr(lasty, DELIMITER[0])) == NULL)
      yptr = y + ylen;

    xnum = strtol(lastx, &endptr, 10);
    xisnum = endptr == xptr ? 1 : 0;
    ynum = strtol(lasty, &endptr, 10);
    yisnum = endptr == yptr ? 1 : 0;

    if (xisnum && !yisnum) return -1;
    if (!xisnum && yisnum) return 1;

    if (xisnum && yisnum) {
      if (xnum != ynum) return xnum < ynum ? -1 : 1;
    } else {
      xn = xptr - lastx;
      yn = yptr - lasty;
      min = xn < yn ? xn : yn;
      if ((res = strncmp(lastx, lasty, min))) return res < 0 ? -1 : 1;
      if (xn != yn) return xn < yn ? -1 : 1;
    }

    lastx = xptr + 1;
    lasty = yptr + 1;
    if (lastx == x + xlen + 1 && lasty == y + ylen + 1) break;
    if (lastx == x + xlen + 1) return -1;
    if (lasty == y + ylen + 1) return 1;
  }

  return 0;
}

int
semver_compare_prerelease (semver_t x, semver_t y) {
  return compare_prerelease(x.prerelease, y.prerelease);
}

int
semver_compare_version (semver_t x, semver_t y) {
  int res;

  if ((res = binary_comparison(x.major, y.major)) == 0) {
    if ((res = binary_comparison(x.minor, y.minor)) == 0) {
      return binary_comparison(x.patch, y.patch);
    }
  }

  return res;
}

int semver_compare (semver_t x, semver_t y) {
  int res;

  if ((res = semver_compare_version(x, y)) == 0) {
    return semver_compare_prerelease(x, y);
  }

  return res;
}

int semver_gt (semver_t x, semver_t y) {
  return semver_compare(x, y) == 1;
}

int semver_lt (semver_t x, semver_t y) {
  return semver_compare(x, y) == -1;
}


int semver_eq (semver_t x, semver_t y) {
  return semver_compare(x, y) == 0;
}

int semver_neq (semver_t x, semver_t y) {
  return semver_compare(x, y) != 0;
}

int semver_gte (semver_t x, semver_t y) {
  return semver_compare(x, y) >= 0;
}

int semver_lte (semver_t x, semver_t y) {
  return semver_compare(x, y) <= 0;
}

int semver_satisfies_caret (semver_t x, semver_t y) {
  if (x.major == y.major) {
    if (x.major == 0) {
        if (x.minor == 0){
          return (x.minor == y.minor) && (x.patch == y.patch);
        }
        else if (x.minor == y.minor){
          return x.patch >= y.patch;
        }
        else{
          return 0;
        }
      }
    else if (x.minor > y.minor){
      return 1;
    }
    else if (x.minor == y.minor)
    {
      return x.patch >= y.patch;
    }
    else {
      return 0;
    }
  }
  return 0;
}

int semver_satisfies_patch (semver_t x, semver_t y) {
  return x.major == y.major
      && x.minor == y.minor;
}


int semver_satisfies (semver_t x, semver_t y, const char *op) {
  int first, second;
  first = op[0];
  second = op[1];

  if (first == SYMBOL_CF)
    return semver_satisfies_caret(x, y);

  if (first == SYMBOL_TF)
    return semver_satisfies_patch(x, y);

  if (first == SYMBOL_EQ)
    return semver_eq(x, y);

  if (first == SYMBOL_GT) {
    if (second == SYMBOL_EQ) {
      return semver_gte(x, y);
    }
    return semver_gt(x, y);
  }

  if (first == SYMBOL_LT) {
    if (second == SYMBOL_EQ) {
      return semver_lte(x, y);
    }
    return semver_lt(x, y);
  }

  return 0;
}

void semver_free (semver_t *x) {
  if (x->metadata) {
    free(x->metadata);
    x->metadata = NULL;
  }
  if (x->prerelease) {
    free(x->prerelease);
    x->prerelease = NULL;
  }
}

static void concat_num (char * str, int x, char * sep) {
  char buf[SLICE_SIZE] = {0};
  if (sep == NULL) sprintf(buf, "%d", x);
  else sprintf(buf, "%s%d", sep, x);
  strcat(str, buf);
}

static void concat_char (char * str, char * x, char * sep) {
  char buf[SLICE_SIZE] = {0};
  sprintf(buf, "%s%s", sep, x);
  strcat(str, buf);
}

void semver_render (semver_t *x, char *dest) {
  concat_num(dest, x->major, NULL);
  concat_num(dest, x->minor, DELIMITER);
  concat_num(dest, x->patch, DELIMITER);
  if (x->prerelease) concat_char(dest, x->prerelease, PR_DELIMITER);
  if (x->metadata) concat_char(dest, x->metadata, MT_DELIMITER);
}

void semver_bump (semver_t *x) {
  x->major++;
}

void semver_bump_minor (semver_t *x) {
  x->minor++;
}

void semver_bump_patch (semver_t *x) {
  x->patch++;
}

static int has_valid_length (const char *s) {
  return strlen(s) <= MAX_SIZE;
}


int semver_is_valid (const char *s) {
  return has_valid_length(s)
      && has_valid_chars(s, VALID_CHARS);
}

int semver_clean (char *s) {
  size_t i, len, mlen;
  int res;
  if (has_valid_length(s) == 0) return -1;

  len = strlen(s);
  mlen = strlen(VALID_CHARS);

  for (i = 0; i < len; i++) {
    if (contains(s[i], VALID_CHARS, mlen) == 0) {
      res = strcut(s, i, 1);
      if(res == -1) return -1;
      --len; --i;
    }
  }

  return 0;
}

static int char_to_int (const char * str) {
  int buf;
  size_t i,len, mlen;
  buf = 0;
  len = strlen(str);
  mlen = strlen(VALID_CHARS);

  for (i = 0; i < len; i++)
    if (contains(str[i], VALID_CHARS, mlen))
      buf += (int) str[i];

  return buf;
}

int semver_numeric (semver_t *x) {
  int num;
  char buf[SLICE_SIZE * 3];
  memset(&buf, 0, SLICE_SIZE * 3);

  if (x->major) concat_num(buf, x->major, NULL);
  if (x->major || x->minor) concat_num(buf, x->minor, NULL);
  if (x->major || x->minor || x->patch) concat_num(buf, x->patch, NULL);

  num = parse_int(buf);
  if(num == -1) return -1;

  if (x->prerelease) num += char_to_int(x->prerelease);
  if (x->metadata) num += char_to_int(x->metadata);

  return num;
}
