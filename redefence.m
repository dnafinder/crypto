function out=redefence(text,key,offset,direction)
% REDEFENCE Cipher encoder/decoder (ACA)
% REDEFENCE is a Rail Fence (zig-zag) transposition variant defined by:
%   - a ROW KEY (a permutation of the rails), which specifies the order in
%     which rails are read off for encryption (and filled for decryption),
%   - an OFFSET into the zig-zag cycle, which shifts the starting position
%     of the rail-writing pattern.
%
% This implementation is a wrapper over railfence.m (extended) and delegates
% the core zig-zag mapping and rail splitting/merging to railfence using:
%   railfence(cleanText, nRails, direction, 'offset', offset, 'roworder', perm)
%
% Text handling:
%   - Only letters A–Z are processed; other characters are ignored.
%
% Syntax:
%   out = redefence(text,key,offset,direction)
%
% Inputs:
%   text      - character array or string scalar to encode/decode
%   key       - rail read-out order as:
%                 * character digits (e.g., '213'),
%                 * numeric scalar (e.g., 213),
%                 * numeric vector (e.g., [2 1 3])
%              The key must be a permutation of 1..R where R = number of rails.
%              ACA typically uses 3–7 rails (i.e., key length 3..7).
%   offset    - nonnegative integer shift into the rail cycle (0-based)
%   direction - 1 to encrypt, -1 to decrypt
%
% Output (structure):
%   out.plain      - processed plaintext (A–Z only)
%   out.key        - original key as provided by the user
%   out.offset     - offset as provided by the user (indispensable metadata)
%   out.encrypted  - processed ciphertext (A–Z only)
%
% Example:
% out = redefence('Hide the gold into the tree stump','213',0,1)
% 
% out = 
% 
%   struct with fields:
% 
%           key: '213'
%        offset: 0
%         plain: 'HIDETHEGOLDINTOTHETREESTUMP'
%     encrypted: 'IEHGLITTERETMHTONHEUDEDOTSP'
% 
% out = redefence('IEHGLITTERETMHTONHEUDEDOTSP','213',0,-1)
% 
% out = 
% 
%   struct with fields:
% 
%           key: '213'
%        offset: 0
%     encrypted: 'IEHGLITTERETMHTONHEUDEDOTSP'
%         plain: 'HIDETHEGOLDINTOTHETREESTUMP'
%
%           Created by Giuseppe Cardillo
%           giuseppe.cardillo.75@gmail.com
%           GitHub (Crypto): https://github.com/dnafinder/crypto


p = inputParser;
addRequired(p,'text',@(x) ischar(x) || (isstring(x) && isscalar(x)));
addRequired(p,'key',@(x) ischar(x) || (isstring(x) && isscalar(x)) || isnumeric(x));
addRequired(p,'offset',@(x) validateattributes(x,{'numeric'}, ...
    {'scalar','real','finite','nonnan','nonempty','integer','>=',0}));
addRequired(p,'direction',@(x) validateattributes(x,{'numeric'}, ...
    {'scalar','real','finite','nonnan','nonempty','integer','nonzero','>=',-1,'<=',1}));
parse(p,text,key,offset,direction);
clear p

if isstring(text); text = char(text); end
if isstring(key);  key  = char(key);  end
assert(ismember(direction,[-1 1]),'Direction must be 1 (encrypt) or -1 (decrypt).')

% Preserve original key (black box)
out.key = key;
out.offset = offset;

% Parse permutation
if isnumeric(key)
    if isscalar(key)
        ks = num2str(key);
        ks = regexprep(ks,'\D','');
        keyDigits = double(ks) - 48;
    else
        keyDigits = key(:).';
    end
else
    ks = regexprep(key,'\D','');
    keyDigits = double(ks) - 48;
end

R = numel(keyDigits);
assert(R>=3 && R<=7,'Rows (key length) must be 3..7.')
assert(numel(unique(keyDigits))==R,'Key digits must not repeat.')
assert(all(ismember(keyDigits,1:R)),'Key must be a permutation of 1..%d.',R)

% Filter A-Z only (REDEFENCE convention)
t = double(upper(text));
t(t<65 | t>90) = [];
clean = char(t);

if isempty(clean)
    if direction == 1
        out.plain = '';
        out.encrypted = '';
    else
        out.encrypted = '';
        out.plain = '';
    end
    return
end

% Delegate to railfence
tmp = railfence(clean,R,direction,'offset',offset,'roworder',keyDigits);

if direction == 1
    out.plain = tmp.plain;
    out.encrypted = tmp.encrypted;
else
    out.encrypted = tmp.encrypted;
    out.plain = tmp.plain;
end

end
