#!/bin/sh

smallstr="/small"
mediumstr="/medium"
largestr="/large"
xlargestr="/xlarge"
smallfile=50001
mediumfile=1000001
largefile=6000001
root_dir="/media/malware/maltrievepulls/"
all_files="$root_dir*"
for file in $all_files
do
  if [ -f $file ]; then
    outstring=($(eval file $file))
    stringsubone="${outstring[1]}"
    case $stringsubone in
      "a") stringsubone="PerlScript";;
      "very") stringsubone="VeryShortFile";;
      "empty") rm $file
               continue;;
      *);;
    esac
    if [ ! -d $root_dir$stringsubone ]; then
      mkdir -p "$root_dir$stringsubone"
      mkdir -p "$root_dir$stringsubone$smallstr"
      mkdir -p "$root_dir$stringsubone$mediumstr"
      mkdir -p "$root_dir$stringsubone$largestr"
      mkdir -p "$root_dir$stringsubone$xlargestr"
    fi
    filesize=$(stat -c %s $file)
    if [[ "$filesize" -le "$smallfile" ]]; then
      mv $file "$root_dir$stringsubone$smallstr/"
    elif [[ "$filesize" -le "$mediumfile" ]]; then
      mv $file "$root_dir$stringsubone$mediumstr/"
    elif [[ "$filesize" -le "$largefile" ]]; then
      mv $file "$root_dir$stringsubone$largestr/"
    else
      mv $file "$root_dir$stringsubone$xlargestr/"
    fi
  fi
done

