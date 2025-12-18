function out=interruptedkey(text,key,interrupt,direction)
% INTERRUPTEDKEY Cipher encoder/decoder (ACA)
% The plaintext is enciphered with 1,2,3 or more letters of the keyword,
% which is interrupted at random, by plaintext word division, or according
% to some other scheme. Return to the first key letter each time the keyword
% is interrupted. (ACA example uses Vigenere.) 
%
% This implementation preserves all non A-Z characters (spaces, punctuation)
% in their original positions, and transforms only letters A-Z.
% With interrupt='word', the keyword restarts at every non-letter separator.
%
% Syntax:
%   out = interruptedkey(text,key,interrupt,direction)
%   out = interruptedkey(text,key,direction)          % interrupt defaults to 'word'
%
% Inputs:
%   text      - char array or string scalar to encode or decode
%   key       - keyword (A-Z only are used internally)
%   interrupt - 'word' (default) or numeric vector of run lengths
%   direction - 1 to encrypt, -1 to decrypt
%
% Output (minimal):
%   out.key        - original key as provided by user
%   out.plain      - processed plaintext (uppercase, same length as input, separators preserved)
%   out.encrypted  - processed ciphertext (uppercase, same length as input, separators preserved)
%
% Example:
% out = interruptedkey('Hide the gold into the tree stump','leprachaun','word',1)
% 
% out = 
% 
%   struct with fields:
% 
%           key: 'leprachaun'
%         plain: 'HIDE THE GOLD INTO THE TREE STUMP'
%     encrypted: 'SMSV ELT RSAU TRIF ELT EVTV DXJDP'
% 
% out = interruptedkey('SMSV ELT RSAU TRIF ELT EVTV DXJDP','leprachaun','word',-1)
% 
% out = 
% 
%   struct with fields:
% 
%           key: 'leprachaun'
%     encrypted: 'SMSV ELT RSAU TRIF ELT EVTV DXJDP'
%         plain: 'HIDE THE GOLD INTO THE TREE STUMP'
%
%           Created by Giuseppe Cardillo
%           giuseppe.cardillo.75@gmail.com
%           GitHub (Crypto): https://github.com/dnafinder/crypto

% -------------------- Optional interrupt handling --------------------
if nargin == 3
    direction = interrupt;
    interrupt = 'word';
end

% -------------------- Input parsing --------------------
p = inputParser;
addRequired(p,'text',@(x) ischar(x) || (isstring(x) && isscalar(x)));
addRequired(p,'key',@(x) ischar(x) || (isstring(x) && isscalar(x)));
addRequired(p,'interrupt',@(x) (ischar(x) || (isstring(x) && isscalar(x))) || ...
    (isnumeric(x) && isvector(x) && ~isempty(x)));
addRequired(p,'direction',@(x) validateattributes(x,{'numeric'}, ...
    {'scalar','real','finite','nonnan','nonempty','integer','nonzero','>=',-1,'<=',1}));
parse(p,text,key,interrupt,direction);
clear p

if isstring(text); text = char(text); end
if isstring(key);  key  = char(key);  end
if isstring(interrupt); interrupt = char(interrupt); end

assert(ismember(direction,[-1 1]),'Direction must be 1 (encrypt) or -1 (decrypt).')

% -------------------- Output: original key --------------------
out.key = key;

% -------------------- Normalize text (preserve separators) --------------------
t = upper(text);
isAZ = (t >= 'A' & t <= 'Z');

% -------------------- Clean key (internal A-Z only) --------------------
k = upper(key);
k = k(k>='A' & k<='Z');
assert(~isempty(k),'Key must contain at least one alphabetic letter A-Z.')
LK = numel(k);

% Trivial: no letters to process
if ~any(isAZ)
    if direction == 1
        out.plain = t;
        out.encrypted = t;
    else
        out.encrypted = t;
        out.plain = t;
    end
    return
end

% -------------------- Build keystream aligned to text positions --------------------
% ks same length as t, but filled only where isAZ==true
ks = repmat(char(0),1,numel(t));

if ischar(interrupt)
    mode = strtrim(interrupt);
    assert(strcmpi(mode,'word'),'interrupt must be ''word'' or a numeric vector.')

    % Restart key after each non-letter separator; ignore consecutive separators.
    keyPos = 1;
    prevWasLetter = false;

    for i = 1:numel(t)
        if isAZ(i)
            if ~prevWasLetter
                keyPos = 1; % restart at word start
            end
            ks(i) = k(keyPos);
            keyPos = keyPos + 1;
            if keyPos > LK, keyPos = 1; end
            prevWasLetter = true;
        else
            prevWasLetter = false;
        end
    end

else
    runs = interrupt(:).';
    validateattributes(runs,{'numeric'},{'real','finite','nonnan','positive','integer'})

    % Apply run lengths over letters only, restarting key at each run boundary.
    letterIdx = find(isAZ);
    LT = numel(letterIdx);

    pos = 1;
    rix = 1;
    while pos <= LT
        n = min(runs(rix), LT - pos + 1);

        block = repmat(k,1,ceil(n/LK));
        block = block(1:n);

        ks(letterIdx(pos:pos+n-1)) = block;

        pos = pos + n;
        rix = rix + 1;
        if rix > numel(runs), rix = 1; end
    end
end

% -------------------- Transform letters using vigenere (extended) --------------------
letters = t(isAZ);
shiftStream = double(ks(isAZ)) - 65; % 0..25

tmp = vigenere(letters,key,direction, ...
    'Mode','add', ...
    'PlainAlphabet','ABCDEFGHIJKLMNOPQRSTUVWXYZ', ...
    'CipherAlphabet','ABCDEFGHIJKLMNOPQRSTUVWXYZ', ...
    'ShiftStream',shiftStream);

% Reinsert into original layout
res = t;
if direction == 1
    res(isAZ) = tmp.encrypted;
    out.plain = t;
    out.encrypted = res;
else
    res(isAZ) = tmp.plain;
    out.encrypted = t;
    out.plain = res;
end

end
