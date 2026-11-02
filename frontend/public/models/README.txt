Model files served to the browser build of Liveness Studio. They are the same files the Java engine loads (models/onnx), and the app
checks each one against the SHA-256 listed in models/onnx/manifest.json before using it.

yunet_2023mar_dynamic.onnx            YuNet face detector (OpenCV Zoo, MIT licence, see YUNET_LICENSE.txt)
minifasnet_minifasnetv2_s2.7.onnx     MiniFASNetV2, MiniVision Silent-Face-Anti-Spoofing (Apache-2.0)
minifasnet_minifasnetv1se_s4.0.onnx   MiniFASNetV1SE, MiniVision Silent-Face-Anti-Spoofing (Apache-2.0)

These public models are NOT evaluated or calibrated for this setup. Nothing here is an accuracy claim.
