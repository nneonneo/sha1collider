## About

Generate two PDFs with different contents but identical SHA1 hashes.

PDFs are rendered into JPGs and merged into the output file. They must have the same page size and page count.

Requires ghostscript, turbojpeg, PIL, and Python 3.

Uses the "shattered" PDF prologue from shattered.io - credit to Marc Stevens et al. for the collision.

Similar to, but more flexible (supports more than one page, arbitrary-sized inputs, etc.) than the collision generator from http://alf.nu/SHA1.

## Usage

Just run `python3 collide.py PDF1.pdf PDF2.pdf`, and it will generate `out-PDF1.pdf` and `out-PDF2.pdf`. These will contain the same content as the original input PDFs, but will have the same SHA1 hash. If the resulting PDFs don't work for you (e.g. they look corrupt, images have artifacts, etc.), try `--progressive` mode.

## Remarks

There are two encoding modes: a more flexible "restart interval" mode and a more compatible "progressive" mode, switched by way of `--progressive`.

Restart intervals allow the image data to be reliably broken up into small chunks. However, some PDF renderers, such as my version of GhostScript, cannot parse the resulting JPEG correctly (as it has comments preceding the restart markers).

Progressive mode works with many smaller PDFs (at lower resolution, for example), but breaks down with larger images. However, it produces PDFs that are broadly compatible because it does not involve bending the JPEG spec. This is the mode used by Google+CWI in generating their own PoC PDF pair.
