function out=adfgx(text,key,direction,varargin)
% ADFGX Cipher encoder/decoder
% In cryptography, the ADFGX cipher was a field cipher used by the German
% Army on the Western Front during World War I. Invented by Lieutenant Fritz
% Nebel (1891–1977) and introduced in March 1918, the cipher was a
% fractionating transposition cipher which combined a modified Polybius
% square with a single columnar transposition. The cipher is named after
% the five possible letters used in the ciphertext: A, D, F, G and X.
% The letters were chosen deliberately because they are very different from
% one another in the Morse code, reducing the possibility of operator error.
%
% English, 26 letters, alphabet is used.
% Only letters A-Z are processed; other characters are ignored.
% J is merged into I.
%
% Syntax: 	out=adfgx(text,key,direction,matrix)
%
%     Input:
%           text - It is a character array or a string scalar to encode or decode
%           key - It is the transposition keyword (character array or string scalar)
%           direction - this parameter can assume only two values:
%                   1 to encrypt
%                  -1 to decrypt.
%           matrix - a scrambled 5x5 Polybius matrix (char 5x5) using the
%                    standard English alphabet without J. If it is empty and
%                    direction is 1, the software will generate it.
%     Output:
%           out - It is a structure
%           out.plain = the plain text (processed)
%           out.key = the used key (processed)
%           out.matrix = the used matrix
%           out.encrypted = the coded text
%
% Examples:
%
% out=adfgx('Hide the gold into the tree stump','leprachaun',1, ...
%           ['BTALP';'DHOZK';'QFVSN';'GICUX';'MREWY'])
%
% out=adfgx('DGFXFFFDDDAAXFGDDADFAXDAAADDDAXXDGFDGGXGDXADFDDFXAADXG', ...
%           'leprachaun',-1, ...
%           ['BTALP';'DHOZK';'QFVSN';'GICUX';'MREWY'])
%
% See also adfgvx, bifid, checkerboard1, checkerboard2, foursquares,
% nihilist, playfair, polybius, threesquares, trifid, twosquares
%
%           Created by Giuseppe Cardillo
%           giuseppe.cardillo.75@gmail.com
%           GitHub (Crypto): https://github.com/dnafinder/crypto

p = inputParser;
addRequired(p,'text',@(x) ischar(x) || (isstring(x) && isscalar(x)));
addRequired(p,'key',@(x) ischar(x) || (isstring(x) && isscalar(x)));
addRequired(p,'direction',@(x) validateattributes(x,{'numeric'}, ...
    {'scalar','real','finite','nonnan','nonempty','integer','nonzero','>=',-1,'<=',1}));
addOptional(p,'matrix',[],@(x) isempty(x) || (ischar(x) && isequal(size(x),[5,5])));
parse(p,text,key,direction,varargin{:});
matrix = p.Results.matrix;
clear p

if isstring(text); text = char(text); end
if isstring(key);  key  = char(key);  end

assert(ismember(direction,[-1 1]),'Direction must be 1 (encrypt) or -1 (decrypt)')

% Alphabet without J:
A = 65:1:90;
A(A==74) = [];

% --- Matrix handling ---
if isempty(matrix)
    assert(direction==1,'This algorithm cannot decode without a matrix')
    cmatrix = reshape(A(randperm(25)),[5,5]);
    out.matrix = char(cmatrix);
else
    cmatrix = double(upper(matrix));
    assert(all(ismember(cmatrix(:),A)), ...
        'Matrix must use standard English alphabet without J letter. J=I')
    assert(numel(unique(cmatrix(:)))==25, ...
        'Matrix must contain 25 unique letters (A-Z without J).')
    out.matrix = upper(matrix);
end
clear A

% --- Filter and normalize text and key ---
ctext = double(upper(text));
ctext(ctext==74) = 73; % J -> I
ctext(ctext<65 | ctext>90) = [];

ckey_raw = double(upper(key));
ckey_raw(ckey_raw==74) = 73; % J -> I
ckey_raw(ckey_raw<65 | ckey_raw>90) = [];

assert(~isempty(ckey_raw),'Key must contain at least one valid letter A-Z.')

out.key = char(ckey_raw);

% Sort letters in the key for columnar transposition
[~,Idx] = sort(ckey_raw);

% ADFGX coordinate symbols
P = 'ADFGX';

switch direction
    case 1 % encrypt
        % Store processed plaintext
        out.plain = char(ctext);

        % Fractionation using the Polybius square
        [~,locb] = ismember(ctext,cmatrix);
        assert(all(locb>0),'Plaintext contains characters not encodable with the given matrix.')

        [I,J] = ind2sub([5,5],locb);

        % Build ADFGX digraph stream
        out1 = reshape([P(I); P(J)],1,[]);
        clear locb I J

        % Columnar transposition
        L = numel(out1);
        C = numel(ckey_raw);
        R = ceil(L/C);

        % Pad to full rectangle (use 'Z' that never appears in ADFGX stream)
        padLen = C*R - L;
        if padLen > 0
            tmp = [out1 repmat('Z',1,padLen)];
        else
            tmp = out1;
        end

        tmp = reshape(tmp,C,R)';     % R x C
        tmp = tmp(:,Idx);           % reorder columns by sorted key

        tmp = tmp(:)';              % read off by columns
        tmp(tmp=='Z') = [];         % remove padding

        out.encrypted = tmp;

        clear tmp out1 L C R padLen

    case -1 % decrypt
        % Store filtered encrypted input
        out.encrypted = char(ctext);

        % Validate ADFGX alphabet
        Pc = double(P);
        assert(all(ismember(ctext,Pc)), ...
            'Ciphertext must contain only letters A, D, F, G, X.')

        L = numel(ctext);
        C = numel(ckey_raw);
        R = ceil(L/C);
        N = C*R;

        tmp = zeros(R,C);

        if L < N
            % Determine which columns are shorter due to padding
            paddingStart = C - N + L + 1;
            tmp(R,paddingStart:C) = 90; % mark padded cells with 'Z'/90

            cwork = ctext;

            for iCol = 1:C
                colPos = Idx(iCol);
                if colPos < paddingStart
                    tmp(:,colPos) = cwork(1:R);
                    cwork(1:R) = [];
                else
                    tmp(1:R-1,colPos) = cwork(1:R-1);
                    cwork(1:R-1) = [];
                end
            end
            clear cwork paddingStart iCol colPos
        else
            tmp2 = reshape(ctext,R,C);
            tmp(:,Idx) = tmp2(:,1:C);
            clear tmp2
        end

        % Recover fractionated stream
        tmp = tmp';
        out1 = tmp(:)';
        out1(out1==90) = []; % remove padding markers

        % Convert ADFGX pairs back to matrix indices
        Rv = out1(1:2:end);
        Cv = out1(2:2:end);

        for k = 1:5
            Rv(Rv==Pc(k)) = k;
            Cv(Cv==Pc(k)) = k;
        end

        ind = sub2ind([5,5],Rv,Cv);
        out.plain = char(cmatrix(ind));

        clear tmp out1 Rv Cv ind k L C R N Pc
end

end
