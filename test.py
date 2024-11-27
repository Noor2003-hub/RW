from farasa import arabic_utils
from farasa import segmentation



# Example text
text = "يدخل الحمام"
print(arabic_utils)
print(segmentation.segmentLine(text))
print(segmentation.getSubPartitions(text,text))
print(segmentation.mostLikelyPartition(text,text))
print(segmentation.getAllPossiblePartitionsOfString(text))
print(segmentation.getProperSegmentation(text))

