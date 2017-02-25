#!/usr/bin/env python3
"""
Generate two PDFs with different contents but identical SHA1 hashes.

PDFs are rendered into JPGs and merged into the output file. They must have the same page size and page count.

Requires ghostscript, turbojpeg, and PIL.

Uses the "shattered" PDF prologue from shattered.io - credit to Marc Stevens et al. for the collision.
"""

from hashlib import sha1, sha256
import tempfile
import subprocess
import os
import sys
import shutil
import itertools
import logging
import re
from PIL import Image

logging.basicConfig(stream=sys.stderr, level=logging.DEBUG, format='%(asctime)s %(levelname)s: %(message)s', datefmt='[%H:%M:%S]')
logger = logging

prefix1 = bytes.fromhex("25 50 44 46 2D 31 2E 33 0A 25 E2 E3 CF D3 0A 0A 0A 31 20 30 20 6F 62 6A 0A 3C 3C 2F 57 69 64 74 68 20 32 20 30 20 52 2F 48 65 69 67 68 74 20 33 20 30 20 52 2F 54 79 70 65 20 34 20 30 20 52 2F 53 75 62 74 79 70 65 20 35 20 30 20 52 2F 46 69 6C 74 65 72 20 36 20 30 20 52 2F 43 6F 6C 6F 72 53 70 61 63 65 20 37 20 30 20 52 2F 4C 65 6E 67 74 68 20 38 20 30 20 52 2F 42 69 74 73 50 65 72 43 6F 6D 70 6F 6E 65 6E 74 20 38 3E 3E 0A 73 74 72 65 61 6D 0A FF D8 FF FE 00 24 53 48 41 2D 31 20 69 73 20 64 65 61 64 21 21 21 21 21 85 2F EC 09 23 39 75 9C 39 B1 A1 C6 3C 4C 97 E1 FF FE 01 73 46 DC 91 66 B6 7E 11 8F 02 9A B6 21 B2 56 0F F9 CA 67 CC A8 C7 F8 5B A8 4C 79 03 0C 2B 3D E2 18 F8 6D B3 A9 09 01 D5 DF 45 C1 4F 26 FE DF B3 DC 38 E9 6A C2 2F E7 BD 72 8F 0E 45 BC E0 46 D2 3C 57 0F EB 14 13 98 BB 55 2E F5 A0 A8 2B E3 31 FE A4 80 37 B8 B5 D7 1F 0E 33 2E DF 93 AC 35 00 EB 4D DC 0D EC C1 A8 64 79 0C 78 2C 76 21 56 60 DD 30 97 91 D0 6B D0 AF 3F 98 CD A4 BC 46 29 B1")
prefix2 = bytes.fromhex("25 50 44 46 2D 31 2E 33 0A 25 E2 E3 CF D3 0A 0A 0A 31 20 30 20 6F 62 6A 0A 3C 3C 2F 57 69 64 74 68 20 32 20 30 20 52 2F 48 65 69 67 68 74 20 33 20 30 20 52 2F 54 79 70 65 20 34 20 30 20 52 2F 53 75 62 74 79 70 65 20 35 20 30 20 52 2F 46 69 6C 74 65 72 20 36 20 30 20 52 2F 43 6F 6C 6F 72 53 70 61 63 65 20 37 20 30 20 52 2F 4C 65 6E 67 74 68 20 38 20 30 20 52 2F 42 69 74 73 50 65 72 43 6F 6D 70 6F 6E 65 6E 74 20 38 3E 3E 0A 73 74 72 65 61 6D 0A FF D8 FF FE 00 24 53 48 41 2D 31 20 69 73 20 64 65 61 64 21 21 21 21 21 85 2F EC 09 23 39 75 9C 39 B1 A1 C6 3C 4C 97 E1 FF FE 01 7F 46 DC 93 A6 B6 7E 01 3B 02 9A AA 1D B2 56 0B 45 CA 67 D6 88 C7 F8 4B 8C 4C 79 1F E0 2B 3D F6 14 F8 6D B1 69 09 01 C5 6B 45 C1 53 0A FE DF B7 60 38 E9 72 72 2F E7 AD 72 8F 0E 49 04 E0 46 C2 30 57 0F E9 D4 13 98 AB E1 2E F5 BC 94 2B E3 35 42 A4 80 2D 98 B5 D7 0F 2A 33 2E C3 7F AC 35 14 E7 4D DC 0F 2C C1 A8 74 CD 0C 78 30 5A 21 56 64 61 30 97 89 60 6B D0 BF 3F 98 CD A8 04 46 29 A1")
jpeg1 = prefix1[149:]
jpeg2 = prefix2[149:]

assert sha1(prefix1).hexdigest() == sha1(prefix2).hexdigest()

class SimpleObject:
    def __init__(self, data):
        self.data = data
    def serialize(self, outfile):
        outfile.write(str(self.data).encode())

class MagicJPEGObject:
    def __init__(self, jpegdata):
        self.data = jpegdata
    def add_properties(self, jpegsize, pdf):
        # width
        pdf.add_object(SimpleObject(jpegsize[0]))
        # height
        pdf.add_object(SimpleObject(jpegsize[1]))
        pdf.add_object(SimpleObject('/XObject'))
        pdf.add_object(SimpleObject('/Image'))
        pdf.add_object(SimpleObject('/DCTDecode'))
        pdf.add_object(SimpleObject('/DeviceRGB'))
        pdf.add_object(SimpleObject(len(self.data)))
    def serialize(self, outfile):
        # format fixed by the SHA1 collision header
        outfile.write(b'<</Width 2 0 R/Height 3 0 R/Type 4 0 R/Subtype 5 0 R/Filter 6 0 R/ColorSpace 7 0 R/Length 8 0 R/BitsPerComponent 8>>\n')
        outfile.write(b'stream\n')
        outfile.write(self.data)
        outfile.write(b'\nendstream')

class StreamObject:
    def __init__(self, data):
        self.data = data
    def serialize(self, outfile):
        outfile.write(b'<</Length %d>>\n' % len(self.data))
        outfile.write(b'stream\n')
        outfile.write(self.data)
        outfile.write(b'\nendstream')

class PagesObject:
    def __init__(self):
        self.pages = []
    def add_page(self, page_oid):
        self.pages.append(page_oid)
    def serialize(self, outfile):
        outfile.write(b'<</Type /Pages  /Count %d  /Kids [%s]>>' % (
            len(self.pages), b' '.join(b'%d 0 R' % pid for pid in self.pages)))

class PDFGenerator:
    def __init__(self):
        self.objects = [None]
        self.rootid = 0

    def add_object(self, obj):
        oid = len(self.objects)
        self.objects.append(obj)
        return oid

    def set_root(self, oid):
        self.rootid = oid

    def serialize(self, outfile):
        outfile.write(b'%PDF-1.3\n'
                      b'%\xe2\xe3\xcf\xd3\n'
                      b'\n')

        xref = [(0, 65535, b'f')]
        for oid in range(1, len(self.objects)):
            xref.append((outfile.tell(), 0, b'n'))
            outfile.write(b'\n%d 0 obj\n' % oid)
            self.objects[oid].serialize(outfile)
            outfile.write(b'\nendobj\n')
        outfile.write(b'\n\n')

        xrefpos = outfile.tell()
        outfile.write(b'xref\n')
        outfile.write(b'%d %d\n' % (0, len(xref)))
        for offs, gen, status in xref:
            outfile.write(b'%010d %05d %c \n' % (offs, gen, status))
        outfile.write(b'\n')

        outfile.write(b'trailer << /Root %d 0 R /Size %d >>\n' % (self.rootid, len(xref)))
        outfile.write(b'\nstartxref\n')
        outfile.write(b'%d\n' % xrefpos)
        outfile.write(b'%%EOF\n')

def add_image_page(pdf, pages_oid, imw, imh, cropx, cropy, cropw, croph, pagew, pageh):
    '''
    Add a page to the PDF that is [pagew x pageh] PDF units in size,
    and which shows /Im0 in the desired crop region
    '''

    content_oid = pdf.add_object(StreamObject(b'''
q
%.8f 0 0 %.8f 0 0 cm
1 0 0 1 %d %d cm
%d 0 0 %d 0 0 cm
/Im0 Do
Q''' % (pagew / cropw, pageh / croph,
        -cropx, cropy + croph - imh,
        imw, imh)))
    page_oid = pdf.add_object(SimpleObject('''<<
/Type /Page
/Parent %(parent)d 0 R
/MediaBox [0 0 %(w)d %(h)d]
/CropBox [0 0 %(w)d %(h)d]
/Contents %(content)d 0 R
/Resources << /XObject <</Im0 1 0 R>> >> >>''' % dict(parent=pages_oid, w=pagew, h=pageh, content=content_oid)))

    pdf.objects[pages_oid].add_page(page_oid)

def test_basicpage():
    from io import BytesIO

    pdf = PDFGenerator()
    w, h = 1024, 740
    jpeg = MagicJPEGObject(open('shattered-1.jpg', 'rb').read())
    pdf.add_object(jpeg)
    jpeg.add_properties((w, h), pdf)

    pages = PagesObject()
    pages_oid = pdf.add_object(pages)
    root_oid = pdf.add_object(SimpleObject('<< /Type /Catalog  /Pages %d 0 R >>' % pages_oid))
    pdf.set_root(root_oid)

    add_image_page(pdf, pages_oid, w, h, 0, 0, 256, 740, 1024, 740)
    add_image_page(pdf, pages_oid, w, h, 256, 0, 256, 740, 1024, 740)
    add_image_page(pdf, pages_oid, w, h, 512, 0, 256, 740, 1024, 740)
    add_image_page(pdf, pages_oid, w, h, 768, 0, 256, 740, 1024, 740)

    outfile = BytesIO()
    pdf.serialize(outfile)
    print(outfile.getvalue().hex())
    assert outfile.getvalue().startswith(prefix1)

def parse_args(argv):
    import argparse

    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('-r', '--resolution', help="PDF resolution to render at, in DPI (default 300)", default=300, type=int)
    parser.add_argument('-q', '--quality', help="JPEG quality to use, 0-100 (default 80)", default=80, type=int)
    parser.add_argument('--progressive', action='store_true',
        help="Use progressive encoding? If not set, this uses a restart interval "
             "encoding scheme which works more often but produces less compatible PDFs.")
    parser.add_argument("file1", help="First input PDF")
    parser.add_argument("file2", help="Second input PDF")

    return parser.parse_args(argv)

def jpeg_comment(n):
    assert n < 65534, "JPEG contains oversized image block; encoding not possible"
    n += 2
    return b'\xff\xfe' + bytes([n>>8, n & 0xff])

def merge_jpegs(j1, j2):
    assert j1[:2] == b'\xff\xd8' and j1[-2:] == b'\xff\xd9', "header or footer unexpected"
    assert j2[:2] == b'\xff\xd8' and j2[-2:] == b'\xff\xd9', "header or footer unexpected"

    re_header = b'(?=\xff[\xd0-\xd7\xda])' # look for restart interval or start of scan
    j1k = re.sub(re_header, b'\xff\xff', j1[2:-2])
    j1s = re.split(b'\xff\xff' + re_header, j1k)

    out = bytearray(0x173 - 129)
    # we have 12 bytes between the end of j1 and j2
    out += jpeg_comment(4)
    out += b'nneo'

    for k1 in j1s:
        out += jpeg_comment(4)
        out += jpeg_comment(len(k1) + 4)
        out += k1

    out += b'\xff\xd9'
    out += b'\xff\xd9'

    out += j2[2:]

    return bytes(out)

def doit(outdir, args):
    pagecounts = [0, 0]

    for i, fn in enumerate([args.file1, args.file2]):
        logger.info("rendering file %d..." % (i+1))
        subprocess.check_call(['gs', '-r%d' % args.resolution, '-sDEVICE=png16m',
            '-o', os.path.join(outdir, 't%d-%%04d.png' % (i+1)), fn])

        for pgn in itertools.count(1):
            if not os.path.exists(os.path.join(outdir, 't%d-%04d.png' % (i+1, pgn))):
                break

        pagecounts[i] = pgn - 1

    if pagecounts[0] != pagecounts[1]:
        raise Exception("Page counts must be equal.")

    pagecount = pagecounts[0]

    if pagecount == 0:
        raise Exception("No pages found - did PDF decoding fail?")

    # find a good packing structure
    basew, baseh = Image.open(os.path.join(outdir, 't1-%04d.png' % pagecount)).size
    rows, cols = 1, 1
    while rows * cols < pagecount:
        if rows * baseh < cols * basew:
            rows += 1
        else:
            cols += 1

    masterw, masterh = basew*cols, baseh*rows
    master1 = Image.new('RGB', (masterw, masterh))
    master2 = Image.new('RGB', (masterw, masterh))

    # pack pages into master images
    logger.info("rendering images")
    page_descs = []
    for i in range(pagecount):
        im1 = Image.open(os.path.join(outdir, 't1-%04d.png' % (i+1)))
        im2 = Image.open(os.path.join(outdir, 't2-%04d.png' % (i+1)))
        if im1.size != im2.size:
            raise Exception("Page %ds aren't the same size!" % (i+1))

        pagew, pageh = im1.size
        r, c = divmod(i, cols)
        px, py, pw, ph = c*basew, r*baseh, basew, baseh
        master1.paste(im1, (px, py, px+pw, py+ph))
        master2.paste(im2, (px, py, px+pw, py+ph))

        page_descs.append((px, py, pw, ph, pagew / args.resolution * 72, pageh / args.resolution * 72))

    # convert images into JPG, with restart interval set to split file into suitable segments
    logger.info("saving master images to TGA")
    master1.save(os.path.join(outdir, 'p1.tga'))
    master2.save(os.path.join(outdir, 'p2.tga'))

    logger.info("converting images to JPG")
    if args.progressive:
        j1enc = ['-progressive']
    else:
        j1enc = ['-restart', '250B']

    subprocess.check_call(['cjpeg', '-quality', str(args.quality)] + j1enc + [
        '-outfile', os.path.join(outdir, 'p1.jpg'),
        '-optimize', '-verbose', '-targa', os.path.join(outdir, 'p1.tga')])
    # image 2 doesn't need restart intervals since it's just pasted right at the end
    subprocess.check_call(['cjpeg', '-quality', str(args.quality),
        '-outfile', os.path.join(outdir, 'p2.jpg'),
        '-optimize', '-verbose', '-targa', os.path.join(outdir, 'p2.tga')])

    with open(os.path.join(outdir, 'p1.jpg'), 'rb') as f1:
        with open(os.path.join(outdir, 'p2.jpg'), 'rb') as f2:
            jpeg_footer = merge_jpegs(f1.read(), f2.read())

    # render PDFs
    logger.info("producing final PDFs")
    pdf = PDFGenerator()
    jpeg = MagicJPEGObject(jpeg1 + jpeg_footer)
    pdf.add_object(jpeg)
    jpeg.add_properties((masterw, masterh), pdf)

    pages = PagesObject()
    pages_oid = pdf.add_object(pages)
    root_oid = pdf.add_object(SimpleObject('<< /Type /Catalog  /Pages %d 0 R >>' % pages_oid))
    pdf.set_root(root_oid)

    for page in page_descs:
        add_image_page(pdf, pages_oid, masterw, masterh, *page)

    with open('out-' + args.file1, 'wb') as outfile:
        pdf.serialize(outfile)

    jpeg.data = jpeg2 + jpeg_footer
    with open('out-' + args.file2, 'wb') as outfile:
        pdf.serialize(outfile)

def main(argv):
    args = parse_args(argv)

    outdir = tempfile.mkdtemp()

    try:
        doit(outdir, args)
    finally:
        shutil.rmtree(outdir)

if __name__ == '__main__':
    import sys
    exit(main(sys.argv[1:]))
