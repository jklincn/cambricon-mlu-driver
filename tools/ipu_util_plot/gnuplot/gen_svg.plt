set terminal svg background rgb "white"
set output output_file
#set xlabel "Time / (ms)"
set xtics rotate by 270
set xtics offset 0,0
set key bottom right
set grid
set multiplot layout layout_x,layout_y title title_name offset 0,-0.02

file_exists(file) = system("[ -f '".file."' ] && echo '1' || echo '0'") + 0

do for [i=1:max_instance_count] {
	file_path=sprintf('%s/dev%dinst%d.csv', input_path, card_id, i)
	if (file_exists(file_path)) {
		y_label=sprintf('Instance %d ipu util / %', i)
		set ylabel y_label
		plot file_path using 3 with lines linestyle 1 lw 2 title ' usage', \
		     file_path using 1 with lines linestyle 2 lw 2 title ' quota'
		unset ylabel
	} else {
		#print 'File not exists, skipping'
	}
}
unset multiplot
