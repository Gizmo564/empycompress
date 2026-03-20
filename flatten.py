import os, shutil

dist = "dist"

# Read all artifact files into memory (avoids same-name dir/file collision)
files = {}
for entry in os.listdir(dist):
    sub = os.path.join(dist, entry)
    if os.path.isdir(sub):
        for fname in os.listdir(sub):
            with open(os.path.join(sub, fname), "rb") as f:
                files[fname] = f.read()

# Remove all subdirectories
for entry in os.listdir(dist):
    sub = os.path.join(dist, entry)
    if os.path.isdir(sub):
        shutil.rmtree(sub)

# Write files directly into dist/
for fname, data in files.items():
    with open(os.path.join(dist, fname), "wb") as f:
        f.write(data)

print("Flattened dist/:", sorted(os.listdir(dist)))
