function out = grandpre(text,key,direction)
% GRANDPRE Cipher encoder/decoder (ACA)
% An n×n square (6≤n≤10) is filled with n-letter words horizontally.
% Each plaintext letter is represented by a 2-digit coordinate (row, column)
% taken from the square. A letter appearing more than once may be enciphered
% by more than one digit-pair (homophonic)
%
% This implementation:
%   - Processes only letters A–Z (others are ignored).
%   - Uses row-major coordinate numbering:
%       rows and columns are numbered 1..n (for n<10),
%       for n=10 they are numbered 0..9, where 0 represents 10. :contentReference[oaicite:2]{index=2}
%   - Encrypts deterministically by cycling through all occurrences of a
%     letter in the square (in row-major order).
%   - Outputs ciphertext as 2-digit pairs separated by single spaces.
%   - Decrypts by reading digit pairs and looking up the square coordinates.
%
% Syntax:
%   out = grandpre(text,key,direction)
%
% Inputs:
%   text      - char vector or string scalar (plaintext or ciphertext)
%   key       - square definition, one of:
%                1) cell array of n strings (each length n) = rows
%                2) char matrix n-by-n                      = square
%                3) string/char with whitespace-separated n row-words
%   direction - 1 encrypt, -1 decrypt
%
% Output (minimal):
%   out.key        - key as provided by user
%   out.plain      - processed plaintext (A–Z only, uppercase) 
%   out.encrypted  - ciphertext pairs (spaces)              
%
% Example (ACA square from Grandpré page):
% K = {'LADYBUGS','AZIMUTHS','CALFSKIN','QUACKISH','UNJOVIAL','EVULSION','ROWDYISM','SEXTUPLY'};
% out = grandpre('HIDE THE GOLD INTO THE TREE STUMP',K,1)
% 
% out = 
% 
%   struct with fields:
% 
%           key: {1×8 cell}
%         plain: 'HIDETHEGOLDINTOTHETREESTUMP'
%     encrypted: '27 23 13 61 26 48 82 17 54 11 74 37 38 84 67 26 27 61 84 71 82 61 18 26 16 24 86'
% 
% out = grandpre('27 23 13 61 26 48 82 17 54 11 74 37 38 84 67 26 27 61 84 71 82 61 18 26 16 24 86',K,-1)
% 
% out = 
% 
%   struct with fields:
% 
%           key: {1×8 cell}
%     encrypted: '27 23 13 61 26 48 82 17 54 11 74 37 38 84 67 26 27 61 84 71 82 61 18 26 16 24 86'
%         plain: 'HIDETHEGOLDINTOTHETREESTUMP'
%
%           Created by Giuseppe Cardillo
%           giuseppe.cardillo.75@gmail.com
%           GitHub (Crypto): https://github.com/dnafinder/crypto

% -------------------- Input parsing --------------------
p = inputParser;
addRequired(p,'text',@(x) ischar(x) || (isstring(x) && isscalar(x)));
addRequired(p,'key', @(x) ~isempty(x));
addRequired(p,'direction',@(x) validateattributes(x,{'numeric'}, ...
    {'scalar','real','finite','nonnan','nonempty','integer','nonzero','>=',-1,'<=',1}));
parse(p,text,key,direction);
clear p

if isstring(text); text = char(text); end

out.key = key;

% -------------------- Build square from key --------------------
S = parseSquareKey(key);        % n-by-n char
n = size(S,1);
assert(n>=6 && n<=10,'Square size must be between 6x6 and 10x10.')
assert(size(S,2)==n,'Square must be n-by-n.')

% Build occurrence lists for deterministic homophonic encryption
occ = buildOccurrences(S);

% -------------------- Process text --------------------
switch direction
    case 1 % Encrypt
        t = double(upper(text));
        t(t<65 | t>90) = [];
        pt = char(t);
        out.plain = pt;

        if isempty(pt)
            out.encrypted = '';
            return
        end

        % Pointers for cycling through occurrences of each letter
        ptr = zeros(1,26);

        toks = cell(1,numel(pt));
        for i = 1:numel(pt)
            ch = pt(i);
            idx = double(ch) - 64; % 1..26
            lst = occ{idx};
            assert(~isempty(lst),'Letter %s not found in the provided square.',ch)

            k = ptr(idx);
            k = mod(k, size(lst,1)) + 1;
            ptr(idx) = k;

            r = lst(k,1);
            c = lst(k,2);

            toks{i} = coordPair(r,c,n);
        end

        out.encrypted = strjoin(toks,' ');

    case -1 % Decrypt
        % Keep digits and spaces for display; parse digits only for decoding
        ct_disp = regexprep(text,'[^\d\s]','');
        ct_disp = strtrim(regexprep(ct_disp,'\s+',' '));
        out.encrypted = ct_disp;

        digitsOnly = regexprep(text,'\D','');
        assert(mod(numel(digitsOnly),2)==0,'Ciphertext must contain an even number of digits (pairs).')

        m = numel(digitsOnly)/2;
        pt = repmat('A',1,m);

        pos = 1;
        for i = 1:m
            d1 = str2double(digitsOnly(pos));
            d2 = str2double(digitsOnly(pos+1));
            pos = pos + 2;

            [r,c] = decodePair(d1,d2,n);
            assert(r>=1 && r<=n && c>=1 && c<=n,'Invalid coordinate %d%d for %dx%d square.',d1,d2,n,n)

            pt(i) = S(r,c);
        end

        out.plain = pt;
end

end

% ======================================================================
% Local functions
% ======================================================================
function S = parseSquareKey(key)
% Accept:
%  - cell array of row strings
%  - char matrix n-by-n
%  - char/string with whitespace-separated row words

if isstring(key) && isscalar(key)
    key = char(key);
end

if ischar(key) && ismatrix(key) && size(key,1) > 1 && size(key,2) > 1
    % char matrix
    S = upper(key);
    S(S< 'A' | S > 'Z') = ' ';
    assert(all(S(:) >= 'A' & S(:) <= 'Z'),'Square must contain only letters A-Z.')
    return
end

if iscell(key)
    rows = key(:).';
elseif ischar(key)
    toks = regexp(key,'\S+','match');
    rows = toks;
else
    error('Unsupported key format. Use cell rows, char matrix, or whitespace-separated row words.')
end

% Normalize rows: keep letters A-Z only
rows2 = cell(size(rows));
for i = 1:numel(rows)
    r = rows{i};
    if isstring(r); r = char(r); end
    r = upper(r);
    r(r<'A' | r>'Z') = [];
    rows2{i} = r;
end

n = numel(rows2);
assert(n>=6 && n<=10,'Number of row-words must be between 6 and 10.')
for i = 1:n
    assert(numel(rows2{i})==n,'Each row word must be exactly %d letters.',n)
end

S = char(zeros(n,n));
for i = 1:n
    S(i,:) = rows2{i};
end
end

function occ = buildOccurrences(S)
% occ{1..26} contains [row col] for each letter in row-major order
n = size(S,1);
occ = cell(1,26);
for r = 1:n
    for c = 1:n
        ch = S(r,c);
        idx = double(ch) - 64;
        if idx >= 1 && idx <= 26
            occ{idx} = [occ{idx}; r c]; 
        end
    end
end
end

function tok = coordPair(r,c,n)
% Encode (r,c) as two digits
if n == 10
    a = mod(r,10); if a==0, a = 0; end
    b = mod(c,10); if b==0, b = 0; end
    if r == 10, a = 0; else, a = r; end
    if c == 10, b = 0; else, b = c; end
    tok = sprintf('%d%d',a,b);
else
    tok = sprintf('%d%d',r,c);
end
end

function [r,c] = decodePair(d1,d2,n)
% Decode two digits to (r,c)
if n == 10
    r = d1; c = d2;
    if r == 0, r = 10; end
    if c == 0, c = 10; end
else
    r = d1; c = d2;
end
end
