function out = digrafid(text,key,period,direction)
% DIGRAFID Cipher encoder/decoder
% DIGRAFID is a fractionating cipher that combines:
%   - a keyed monoalphabetic substitution on a 27-symbol alphabet
%     (A–Z plus the period '.'),
%   - with a trifid-style digit-triple fractionation of order 3 or 4.
%
% Each plaintext digraph (pair of symbols) is mapped to a three-digit
% number in base 9, the digit stream is fractionated in blocks of
% length PERIOD, then regrouped into new triples and mapped back to
% ciphertext digraphs using the same keyed 27-symbol alphabet.
%
% This implementation preserves only A–Z (letters) from the input text.
% All other characters (spaces, punctuation, digits) are ignored during
% the transformation. A trailing '.' is used internally as padding when
% the number of letters is odd and is removed on decryption.
%
% Syntax:
%   out = digrafid(text,key,period,direction)
%
% Input:
%   text      - character array to encode or decode
%   key       - character array used to generate the keyed alphabet
%               (only A–Z are used; other characters are ignored)
%   period    - positive integer, fractionation block length (ACA usually 3 or 4)
%   direction - 1 to encrypt, -1 to decrypt
%
% Output:
%   out       - structure with fields:
%                 out.plain      : the plaintext (uppercase, letters only)
%                 out.key        : the cleaned key actually used
%                 out.period     : the fractionation period
%                 out.encrypted  : the ciphertext (uppercase, A–Z and '.')
%
% Example:
%
%   out = digrafid('Hide the gold into the tree stump','leprachaun',3,1)
%
%   out =
%
%     struct with fields:
%
%         plain: 'HIDETHEGOLDINTOTHETREESTUMP'
%           key: 'LEPRACHAUN'
%        period: 3
%     encrypted: 'UHAHGKEVJABAUT.QHSQHSCBFHA.O'
%
%   out = digrafid('UHAHGKEVJABAUT.QHSQHSCBFHA.O','leprachaun',3,-1)
%
%   out =
%
%     struct with fields:
%
%     encrypted: 'UHAHGKEVJABAUT.QHSQHSCBFHA.O'
%           key: 'LEPRACHAUN'
%        period: 3
%         plain: 'HIDETHEGOLDINTOTHETREESTUMP'
%
%           Created by Giuseppe Cardillo
%           giuseppe.cardillo.75@gmail.com

% -------------------- Input parsing --------------------
p = inputParser;
addRequired(p,'text',@(x) ischar(x));
addRequired(p,'key',@(x) ischar(x));
addRequired(p,'period',@(x) validateattributes(x,{'numeric'}, ...
    {'scalar','real','finite','nonnan','nonempty','integer','positive'}));
addRequired(p,'direction',@(x) validateattributes(x,{'numeric'}, ...
    {'scalar','real','finite','nonnan','nonempty','integer','nonzero','>=',-1,'<=',1}));
parse(p,text,key,period,direction);
clear p

% -------------------- Build keyed 27-symbol alphabet --------------------
% Keep only A–Z from the key
ckey = double(upper(key));
ckey(ckey < 65 | ckey > 90) = [];
% Chars of the key must be chosen only once (stable)
ckey = unique(ckey,'stable');

% Base alphabet A–Z
A = 65:90;

% Remaining letters, then add '.' (ASCII 46) as the 27th symbol
A2 = A(~ismember(A,ckey));
alphabet = char([ckey A2 46]);

% Store cleaned key
out.key = char(ckey);
out.period = period;

% -------------------- Preprocess text --------------------
switch direction
    case 1 % Encrypt
        % Keep only letters A–Z from the input text
        t = double(upper(text));
        t(t < 65 | t > 90) = [];
        ctext = char(t);
        out.plain = ctext;
    case -1 % Decrypt
        % For ciphertext we keep A–Z and '.'
        t = double(upper(text));
        t(~((t >= 65 & t <= 90) | t == 46)) = [];
        ctext = char(t);
        out.encrypted = ctext;
end
clear t

% -------------------- Common checks --------------------
if isempty(ctext)
    % Nothing to do
    switch direction
        case 1
            out.encrypted = '';
        case -1
            out.plain = '';
    end
    return
end

% -------------------- Encrypt --------------------
if direction == 1
    % Work on letters only; '.' will be used only as internal padding
    % Map plaintext to the working alphabet (A–Z plus '.')
    L = length(ctext);
    if mod(L,2) ~= 0
        % Pad with '.' if odd length
        ctext = [ctext '.'];
        L = L + 1;
    end

    % Map chars to indices 0..26 in the keyed alphabet
    [~,locb] = ismember(double(ctext),double(alphabet));
    assert(all(locb > 0),'Text contains characters not in the working alphabet.');
    idx = locb - 1; % 0..26
    clear locb

    ndig = L/2;
    D = zeros(3,ndig); % digit triples in 1..9

    % Map each digraph to a 3-digit base-9 number
    for k = 1:ndig
        a = idx(2*k-1);
        b = idx(2*k);
        N = a*27 + b; % 0..728
        d1 = floor(N/81);
        remN = N - d1*81;
        d2 = floor(remN/9);
        d3 = remN - d2*9;
        D(:,k) = [d1+1; d2+1; d3+1]; % store digits in 1..9
    end
    clear idx k N d1 d2 d3 remN

    % Fractionation in blocks of size PERIOD (trifid-style)
    Denc = zeros(size(D));
    col = 1;
    while col <= ndig
        block = min(period, ndig - col + 1);
        Db = D(:,col:col+block-1); % 3 x block

        % Flatten by rows: [row1, row2, row3]
        v = [Db(1,:) Db(2,:) Db(3,:)];

        % Regroup into 3 x block (column-major) – invertible with the
        % decryption routine below
        Eb = reshape(v,3,[]);

        Denc(:,col:col+block-1) = Eb;
        col = col + block;
    end
    clear Db Eb v col block

    % Convert fractionated triples back to digraphs
    res = repmat('A',1,2*ndig);
    for k = 1:ndig
        d1 = Denc(1,k) - 1;
        d2 = Denc(2,k) - 1;
        d3 = Denc(3,k) - 1;
        N = d1*81 + d2*9 + d3; % 0..728
        a = floor(N/27);
        b = N - a*27;
        res(2*k-1) = alphabet(a+1);
        res(2*k)   = alphabet(b+1);
    end
    clear D Denc d1 d2 d3 N a b k ndig

    out.encrypted = res;
    return
end

% -------------------- Decrypt --------------------
% Map ciphertext symbols (A–Z and '.') to indices 0..26
L = length(ctext);
assert(mod(L,2) == 0,'Ciphertext length must be even after removing spaces.');

[~,locb] = ismember(double(ctext),double(alphabet));
assert(all(locb > 0),'Ciphertext contains characters not in the working alphabet.');
idx = locb - 1; % 0..26
clear locb

ndig = L/2;
Denc = zeros(3,ndig);

% Convert digraphs to digit triples in 1..9
for k = 1:ndig
    a = idx(2*k-1);
    b = idx(2*k);
    N = a*27 + b; % 0..728
    d1 = floor(N/81);
    remN = N - d1*81;
    d2 = floor(remN/9);
    d3 = remN - d2*9;
    Denc(:,k) = [d1+1; d2+1; d3+1];
end
clear idx k N d1 d2 d3 remN

% Inverse fractionation, blockwise
D = zeros(size(Denc));
col = 1;
while col <= ndig
    block = min(period, ndig - col + 1);
    Eb = Denc(:,col:col+block-1); % 3 x block

    % Invert Eb = reshape(v,3,[]) done at encryption:
    % linear order Eb(:) is v(:) = [row1 row2 row3]
    v = reshape(Eb,1,[]); % 1 x (3*block)
    row1 = v(1:block);
    row2 = v(block+1:2*block);
    row3 = v(2*block+1:3*block);
    Db = [row1; row2; row3];

    D(:,col:col+block-1) = Db;
    col = col + block;
end
clear Eb v row1 row2 row3 Db col block

% Convert digit triples back to digraphs
res = repmat('A',1,2*ndig);
for k = 1:ndig
    d1 = D(1,k) - 1;
    d2 = D(2,k) - 1;
    d3 = D(3,k) - 1;
    N = d1*81 + d2*9 + d3; % 0..728
    a = floor(N/27);
    b = N - a*27;
    res(2*k-1) = alphabet(a+1);
    res(2*k)   = alphabet(b+1);
end
clear D d1 d2 d3 N a b k ndig alphabet

% Drop trailing padding '.' if present
if res(end) == '.'
    res(end) = [];
end

out.plain = res;
