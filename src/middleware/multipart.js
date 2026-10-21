/**
 * Pure Node.js streaming parser for multipart/form-data without external dependencies.
 * Handles form fields and uploaded file buffers with boundary parsing.
 */
export async function parseMultipartFormData(req, maxSizeBytes = 25 * 1024 * 1024) {
  return new Promise((resolve, reject) => {
    const contentType = req.headers['content-type'] || '';
    if (!contentType.includes('multipart/form-data')) {
      return reject(new Error('Expected multipart/form-data content type'));
    }

    const match = contentType.match(/boundary=(?:"([^"]+)"|([^;]+))/i);
    if (!match) {
      return reject(new Error('Multipart boundary not found in Content-Type'));
    }

    const boundary = match[1] || match[2];
    const boundaryBuffer = Buffer.from(`--${boundary}`);
    const endBoundaryBuffer = Buffer.from(`--${boundary}--`);

    const chunks = [];
    let totalSize = 0;

    req.on('data', (chunk) => {
      totalSize += chunk.length;
      if (totalSize > maxSizeBytes) {
        req.destroy();
        return reject(new Error(`Payload exceeds maximum allowed size of ${maxSizeBytes / (1024 * 1024)}MB`));
      }
      chunks.push(chunk);
    });

    req.on('end', () => {
      try {
        const fullBuffer = Buffer.concat(chunks);
        const result = { fields: {}, files: {} };

        // Split buffer by boundary
        let currentIndex = 0;
        const parts = [];

        while (currentIndex < fullBuffer.length) {
          const boundaryIndex = fullBuffer.indexOf(boundaryBuffer, currentIndex);
          if (boundaryIndex === -1) break;

          const nextBoundaryIndex = fullBuffer.indexOf(boundaryBuffer, boundaryIndex + boundaryBuffer.length);
          if (nextBoundaryIndex === -1) {
            // Check for end boundary
            break;
          }

          const partBuffer = fullBuffer.subarray(boundaryIndex + boundaryBuffer.length, nextBoundaryIndex);
          parts.push(partBuffer);
          currentIndex = nextBoundaryIndex;
        }

        for (const part of parts) {
          // Split headers and body at \r\n\r\n
          const headerEndIndex = part.indexOf(Buffer.from('\r\n\r\n'));
          if (headerEndIndex === -1) continue;

          const headerString = part.subarray(0, headerEndIndex).toString('utf8');
          // Body is between headerEndIndex + 4 and end - 2 (to trim trailing \r\n)
          let bodyBuffer = part.subarray(headerEndIndex + 4);
          if (bodyBuffer.length >= 2 && bodyBuffer[bodyBuffer.length - 2] === 0x0D && bodyBuffer[bodyBuffer.length - 1] === 0x0A) {
            bodyBuffer = bodyBuffer.subarray(0, bodyBuffer.length - 2);
          }

          const dispositionMatch = headerString.match(/Content-Disposition:\s*form-data;\s*name="([^"]+)"(?:;\s*filename="([^"]*)")?/i);
          if (!dispositionMatch) continue;

          const fieldName = dispositionMatch[1];
          const filename = dispositionMatch[2];

          if (filename !== undefined) {
            // File upload
            const contentTypeMatch = headerString.match(/Content-Type:\s*([^\r\n]+)/i);
            const reportedMime = contentTypeMatch ? contentTypeMatch[1].trim() : 'application/octet-stream';

            result.files[fieldName] = {
              originalName: filename,
              reportedMime,
              buffer: bodyBuffer,
              size: bodyBuffer.length
            };
          } else {
            // Regular form field
            result.fields[fieldName] = bodyBuffer.toString('utf8');
          }
        }

        resolve(result);
      } catch (err) {
        reject(err);
      }
    });

    req.on('error', (err) => reject(err));
  });
}
