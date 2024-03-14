:<<!
irrational head_file check:
	find irrational head file used in each module, while the head file is not belong to the module itself, folder 'include' and 'core'.
irrational declaration check:
	find irrational structure declaration used in some head files, while these head files are in the folder 'include', and
	those irrational structure is defined in private module.
!


dir='../'
include=${dir}'include'
core=${dir}'core'

function remove_temp_file()
{
	rm -f temp
	rm -f temp1
	rm -f temp2
	rm -f temp3
}

#find the module folder except 'tools' and '.git'
function find_folder()
{
	rm -f module_folder
	remove_temp_file
	find $dir -type d > temp
	while read LINE
	do
		echo ${LINE#*/} >> temp1
	done < temp
	while read LINE
	do
		echo ${LINE%%/*} >> temp2
	done < temp1
	sort -u temp2 > temp3
	grep -v 'tools\|\.' temp3 > temp
	while read LINE
	do
		if [[ $LINE != '' ]]; then
			echo $dir$LINE >> module_folder
		fi
	done < temp

	remove_temp_file
}

#get the whole head file used in private module
function get_module_include()
{
	name=$1
	rm -f module_include
	remove_temp_file

	grep -rn "#include" $name > temp

	#avoid error when there is no head file in folder
	if [ $? -ne 0 ]; then
		echo ^^^ > temp
	fi

	#remove the string on the left of the first #include including itself
	while read LINE
	do
		echo ${LINE#*#include} >> temp1
	done < temp

	#remove the strings which contain linux, "<" or "\.c"
	cat temp1 | grep -v linux | grep -v "<" | grep -v "\.c" > temp2

	#remove the '\"' in the string
	sed -i "s/\"//g" temp2

	#remove the string on the left of the last / including itself
	while read LINE
	do
		echo ${LINE##*/} >> temp3
	done < temp2
	rm -f temp

	#avoid error like aa.h^M
	while read LINE
	do
		echo ${LINE%.h*}'.h' >> temp
	done < temp3
	rm -f temp1

	#avoid error when no head file in folder
	while read LINE
	do
		if [[ $LINE == '^^^.h' || $LINE == '.h' ]]; then
			echo ^^^ >> temp1
		else
			echo $LINE >> temp1
		fi
	done < temp

	#remove the same head file
	sort -u temp1 > module_include
	remove_temp_file
}

function get_correct_include()
{
	name=$1
	rm -f correct_include
	remove_temp_file

	#get the head file in private module
	find $name -name *.h > temp

	#keep pace with the error avoid in the function: get_module_include
	echo ^^^ >> temp

	while read LINE
	do
		echo ${LINE##*/} >> temp1
	done < temp
	sort -u temp1 >> correct_include

	remove_temp_file

	#get the head file in folder "include"
	find $include -name *.h > temp
	echo ^^^ >> temp
	while read LINE
	do
		echo ${LINE##*/} >> temp1
	done < temp
	sort -u temp1 >> correct_include

	remove_temp_file

	#get the head file in folder "core"
	find $core -name *.h > temp
	echo ^^^ >> temp
	while read LINE
	do
		echo ${LINE##*/} >> temp1
	done < temp
	sort -u temp1 >> correct_include

	remove_temp_file

	#add some special head file to the correct_include
	echo "functions.h" > temp
	echo "generic.h" >> temp
	echo "macros.h" >> temp
	echo "symbols.h" >> temp
	echo "types.h" >> temp
	sort -u temp >> correct_include
	remove_temp_file
}

function check_include()
{
	name=$1
	remove_temp_file
	tag=0
	while read LINE
	do
		#find the similiar string in correct_include compared with module_include
		grep ${LINE} correct_include > inc

		#if the string in module_include has nothing in common with the correct_include, and the string is not '', print
		if [[ $? -ne 0 && $LINE != '' ]]; then
			if [ $tag == 0 ]; then
				echo $name------
				tag=1
			fi
			echo ${LINE}

		#if the string isn't absolutely same with any string in correct_include, print
		else
			flag=1
			while read line0
			do
				if [[ ${LINE} == ${line0} ]]; then
					flag=0
					break
				fi
			done < inc
			if [ $flag == 1 ]; then
				if [ $tag == 0 ]; then
					echo $name-----
					tag=1
				fi
				echo ${LINE}
			fi
		fi
	done < module_include
	if [ $tag == 1 ]; then
		echo ----------------------------------
	fi
	rm -f inc
	remove_temp_file
}

function check_declare()
{
	remove_temp_file
	rm -f include_declare
	#find the structure defination and declaration we need
	grep -rn "struct " $include | grep ";" | grep -v '=\|,\|(\|*\|\[\|extern' > temp

	#get the clear one like "struct sth;" or "struct sth var;"and the corresponding head file
	while read LINE
	do
		echo 'struct'${LINE#*struct}'---------'${LINE%.h*}'.h' >> temp1
	done < temp
	sort -u temp1 > temp2
	while read LINE
	do
		#count the num of ' ' in the string
		count=$(echo $LINE | awk -F' ' '{print NF-1}')
		if [ $count == 1 ]; then
			echo $LINE
		fi
	done < temp2
	remove_temp_file
}

echo "irrational head_file check======================"
find_folder
while read line
do
	get_module_include $line
	get_correct_include $line
	check_include $line
done < module_folder
echo "========================================================================="
echo "irrational declaration check======================"
check_declare
echo "========================================================================="

rm -f module_folder
rm -f module_include
rm -f correct_include
