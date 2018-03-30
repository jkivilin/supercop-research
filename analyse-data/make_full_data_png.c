#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <gd.h>
#include <assert.h>


unsigned int line_get_max_value(char *line, double *count, double *sum)
{
	char *pc;
	int x, ret;
	unsigned int max_value = 0, value;

	/* first is x */
	ret = sscanf(line, "%u", &x);
	assert(ret == 1);

	pc = strstr(line, " ");
	if (!pc)
		return 0;
	pc++;
	do {
		ret = sscanf(pc, "%u", &value);
		if (ret == 1) {
			if (value > max_value)
				max_value = value;
			(*sum)+=value;
			(*count)++;
		}

		pc = strstr(pc, " ");
		if (pc)
			pc++;
	} while(pc);
	return max_value;
}

unsigned int get_data_lines(const char *filename, unsigned int *pmaxv, double *pavg)
{
	char line[1024];
	FILE *fp;
	unsigned int num_lines = 0;
	unsigned int max_value = 0, value;
	double sum = 0;
	double count = 0;

	fp = fopen(filename, "r");
	assert(fp != NULL);

	while (fgets(line, sizeof(line), fp)) {
		int pos = 0;

		while (isspace(line[pos]))
			pos++;

		if (line[pos] == '#')
			continue;

		num_lines++;

		value = line_get_max_value(&line[pos], &count, &sum);
		if (value > max_value)
			max_value = value;
	}

	fclose(fp);

	if (pmaxv)
		*pmaxv = max_value;
	if (pavg)
		*pavg = sum/count;

	return num_lines;
}

unsigned int line_add_to_img(char *line, int color, gdImagePtr im, unsigned int maxv)
{
	char *pc;
	int x, ret;
	unsigned int max_value = 0, value;

	/* first is x */
	ret = sscanf(line, "%u", &x);
	assert(ret == 1);

	pc = strstr(line, " ");
	if (!pc)
		return 0;
	pc++;
	do {
		ret = sscanf(pc, "%u", &value);
		if (ret == 1) {
			gdImageSetPixel(im, x, maxv-value, color);
		}

		pc = strstr(pc, " ");
		if (pc)
			pc++;
	} while(pc);
	return max_value;
}

void add_data_points_to_img(const char *filename, int color, gdImagePtr im, unsigned int maxv)
{
	char line[1024];
	FILE *fp;

	fp = fopen(filename, "r");
	assert(fp != NULL);

	while (fgets(line, sizeof(line), fp)) {
		int pos = 0;

		while (isspace(line[pos]))
			pos++;

		if (line[pos] == '#')
			continue;

		line_add_to_img(&line[pos], color, im, maxv);
	}

	fclose(fp);
}

void img_normalize(gdImagePtr im)
{
	unsigned int x, y;
	unsigned int blackest = 0xff;
	unsigned int whitest = 0;
	unsigned int cur;
	int color;

	for (x = 0; x < im->sx; x++) {
		for (y = 0; y < im->sy; y++) {
			color = gdImageGetPixel(im, x, y);
			cur = gdImageBlue(im, color);

			/* negate color */
			cur = (0xff - cur) & 0xff;

			if (cur < blackest)
				blackest = cur;
			if (cur > whitest && cur != 0xff)
				whitest = cur;
		}
	}

	for (x = 0; x < im->sx; x++) {
		for (y = 0; y < im->sy; y++) {
			color = gdImageGetPixel(im, x, y);

			cur = gdImageBlue(im, color);

			/* negate color */
			cur = (0xff - cur) & 0xff;

			if (cur != 0xff) {
				cur = cur - blackest;
				cur = (double)cur * (0xff/2.0) / (0xff - blackest);
				cur = cur > 0xff ? 0xff : cur;
			}

			color = gdImageColorAllocate(im, cur, cur, cur);
			gdImageSetPixel(im, x, y, color);
		}
	}
}

int main(int argc, const char *argv[])
{
	unsigned int max_value;
	double avg;
	unsigned int max_x, max_y;
	gdImagePtr im, imout;
	int white, black;
	FILE *pngout;

	assert (argc != 2);

	pngout = fopen(argv[2], "wb");
	assert(pngout != NULL);

	max_x = get_data_lines(argv[1], &max_value, &avg);

	printf("avg: %f\n", avg);
	im = gdImageCreateTrueColor(4096, max_y = avg * 2);
	imout = gdImageCreateTrueColor(1024, 1024);

	black = gdImageColorAllocate(im, 0, 0, 0);
	white = gdImageColorAllocate(im, 255, 255, 255);

	/* Set image black (all zeros, better for memory usage (when MM detects
	 * zero pages).
	 */
#if 0
	/* Black is default background color for truecolor images, so do
	 * nothing.
	 */
	{
		unsigned int x, y;
		for (x = 0; x < im->sx; x++) {
			for (y = 0; y < im->sy; y++) {
				gdImageSetPixel(im, x, y, black);
			}
		}
	}
#endif

	add_data_points_to_img(argv[1], white, im, max_y);

	gdImageCopyResampled(imout, im, 0, 0, 0, 0,
			     imout->sx, imout->sy,
			     im->sx, im->sy);
	gdImageDestroy(im);

	img_normalize(imout);
	gdImagePngEx(imout, pngout, 9);
	gdImageDestroy(imout);

	fclose(pngout);

	return 0;
}
