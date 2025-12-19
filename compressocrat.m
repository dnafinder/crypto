function out = compressocrat(text,key,direction)
% COMPRESSOCRAT Cipher encoder/decoder (ACA)
% Compressocrat is a fractionated cipher based on an "irregular" (Huffman-like)
% compression alphabet that maps plaintext letters to digit strings over {1,2,3}.
% Encipherment:
%   1) Map plaintext letters A–Z to the irregular digit strings.
%   2) Concatenate the digits and group into triples.
%   3) If total digits are not a multiple of 3, append digit '1' once or twice.
%   4) Map each digit triple to a ciphertext symbol using a keyed 27-symbol
%      alphabet (A–Z plus '.')
%
% Decipherment:
%   1) Map ciphertext symbols back to digit triples (111..333) using the same key.
%   2) Concatenate digits; try removing 0, 1, or 2 trailing '1' padding digits.
%   3) Decode the irregular digit stream back to letters (prefix-code / greedy).
%
% Text handling:
%   - Only letters A–Z are processed from plaintext; other characters are ignored.
%   - For ciphertext, only A–Z and '.' are processed; other characters are ignored.
%
% Syntax:
%   out = compressocrat(text,key,direction)
%
% Inputs:
%   text      - char vector or string scalar
%   key       - keyword used to generate the keyed ciphertext alphabet
%   direction - 1 encrypt, -1 decrypt
%
% Output (minimal):
%   out.key        - original key as provided by user
%   out.plain      - processed plaintext (A–Z only, uppercase) [encrypt]
%   out.encrypted  - processed ciphertext (A–Z and '.', uppercase) [decrypt]
%
% Example:
%  out = compressocrat('Hide the gold into the tree stump','leprachaun',1)
% 
% out = 
% 
%   struct with fields:
% 
%           key: 'leprachaun'
%         plain: 'HIDETHEGOLDINTOTHETREESTUMP'
%     encrypted: 'PWFQBYVUGGZJADPQMYQRBULVB'
%
%  out = compressocrat('PWFQBYVUGGZJADPQMYQRBULVB','leprachaun',-1)
% 
% out = 
% 
%   struct with fields:
% 
%           key: 'leprachaun'
%     encrypted: 'PWFQBYVUGGZJADPQMYQRBULVB'
%         plain: 'HIDETHEGOLDINTOTHETREESTUMP'
%
%           Created by Giuseppe Cardillo
%           giuseppe.cardillo.75@gmail.com
%           GitHub (Crypto): https://github.com/dnafinder/crypto

% -------------------- Input parsing --------------------
p = inputParser;
addRequired(p,'text',@(x) ischar(x) || (isstring(x) && isscalar(x)));
addRequired(p,'key', @(x) ischar(x) || (isstring(x) && isscalar(x)));
addRequired(p,'direction',@(x) validateattributes(x,{'numeric'}, ...
    {'scalar','real','finite','nonnan','nonempty','integer','nonzero','>=',-1,'<=',1}));
parse(p,text,key,direction);
clear p

if isstring(text); text = char(text); end
if isstring(key);  key  = char(key);  end
assert(ismember(direction,[-1 1]),'Direction must be 1 (encrypt) or -1 (decrypt).')

out.key = key;

% -------------------- Build keyed 27-symbol alphabet (A–Z + '.') --------------------
ckey = double(upper(key));
ckey(ckey < 65 | ckey > 90) = [];
ckey = unique(ckey,'stable');

A = 65:90;
A2 = A(~ismember(A,ckey));
alphabet = char([ckey A2 46]); % '.' as 27th

% Coordinate table for 3x3x3 (Trifid-style): columns correspond to alphabet order
C = [ ...
    1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 3 3 3 3 3 3 3 3 3; ...
    1 1 1 2 2 2 3 3 3 1 1 1 2 2 2 3 3 3 1 1 1 2 2 2 3 3 3; ...
    1 2 3 1 2 3 1 2 3 1 2 3 1 2 3 1 2 3 1 2 3 1 2 3 1 2 3];

% -------------------- Irregular compression alphabet A–Z -> digit strings --------------------
% (from ACA Compressocrat sheet)
codes = cell(1,26);
codes{1}  = '13';       % A
codes{2}  = '32112';    % B
codes{3}  = '1112';     % C
codes{4}  = '213';      % D
codes{5}  = '31';       % E
codes{6}  = '3213';     % F
codes{7}  = '32113';    % G
codes{8}  = '113';      % H
codes{9}  = '322';      % I
codes{10} = '321112';   % J
codes{11} = '11112';    % K
codes{12} = '212';      % L
codes{13} = '2111';     % M
codes{14} = '23';       % N
codes{15} = '22';       % O
codes{16} = '3212';     % P
codes{17} = '11113';    % Q
codes{18} = '323';      % R
codes{19} = '112';      % S
codes{20} = '12';       % T
codes{21} = '1113';     % U
codes{22} = '11111';    % V
codes{23} = '2112';     % W
codes{24} = '321111';   % X
codes{25} = '2113';     % Y
codes{26} = '321113';   % Z

% Reverse map for decoding
rev = containers.Map;
for i = 1:26
    rev(codes{i}) = char(64+i);
end

% -------------------- Encrypt --------------------
if direction == 1
    t = double(upper(text));
    t(t<65 | t>90) = [];
    pt = char(t);
    out.plain = pt;

    if isempty(pt)
        out.encrypted = '';
        return
    end

    % Step 1: irregular encoding to digit stream
    dig = '';
    for i = 1:numel(pt)
        idx = double(pt(i)) - 64;
        dig = [dig codes{idx}]; %#ok<AGROW>
    end

    % Step 3: pad with '1' to multiple of 3
    r = mod(numel(dig),3);
    if r ~= 0
        dig = [dig repmat('1',1,3-r)];
    end

    % Step 4: map triples to ciphertext symbols
    m = numel(dig)/3;
    ct = repmat('A',1,m);

    for i = 1:m
        a = dig(3*i-2) - '0';
        b = dig(3*i-1) - '0';
        c = dig(3*i)   - '0';
        assert(all([a b c] >= 1 & [a b c] <= 3),'Internal digit stream must use only 1..3.')

        % find column in C matching triple
        col = find(C(1,:)==a & C(2,:)==b & C(3,:)==c,1);
        ct(i) = alphabet(col);
    end

    out.encrypted = ct;
    return
end

% -------------------- Decrypt --------------------
% Clean ciphertext: keep A–Z and '.'
u = double(upper(text));
u(~((u>=65 & u<=90) | u==46)) = [];
ct = char(u);
out.encrypted = ct;

if isempty(ct)
    out.plain = '';
    return
end

% Map ciphertext symbols to digit triples
dig = '';
for i = 1:numel(ct)
    [~,loc] = ismember(double(ct(i)),double(alphabet));
    assert(loc > 0,'Ciphertext contains characters not in the keyed alphabet.')
    triple = C(:,loc).';
    dig = [dig char(triple + '0')]; %#ok<AGROW>
end

% Try decoding with 0/1/2 trailing '1' removed (padding)
plain = '';
ok = false;
for trim = 0:2
    if trim > 0
        if numel(dig) < trim || any(dig(end-trim+1:end) ~= '1')
            continue
        end
        cand = dig(1:end-trim);
    else
        cand = dig;
    end

    [pt,success] = decodeIrregular(cand,rev);
    if success
        plain = pt;
        ok = true;
        break
    end
end

assert(ok,'Failed to decode: digit stream does not match the irregular alphabet (wrong key or corrupted text).')

out.plain = plain;

end

% ======================================================================
% Local decoder: greedy prefix-code decode
% ======================================================================
function [pt,success] = decodeIrregular(dig,rev)
pt = '';
buf = '';
success = false;

for i = 1:numel(dig)
    ch = dig(i);
    if ch < '1' || ch > '3'
        return
    end
    buf = [buf ch]; %#ok<AGROW>

    if isKey(rev,buf)
        pt = [pt rev(buf)]; %#ok<AGROW>
        buf = '';
    end
end

% Must end on a code boundary
if isempty(buf)
    success = true;
end
end
