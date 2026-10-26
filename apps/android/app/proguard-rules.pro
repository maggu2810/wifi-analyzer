# kotlinx.serialization: keep generated serializers of the decoded-document model.
-keepattributes *Annotation*, InnerClasses
-keepclassmembers class de.maggu2810.android.wifianalyzer.** {
    *** Companion;
}
-keepclasseswithmembers class de.maggu2810.android.wifianalyzer.** {
    kotlinx.serialization.KSerializer serializer(...);
}
